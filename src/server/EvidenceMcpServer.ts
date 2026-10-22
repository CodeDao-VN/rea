import type {
  Implementation,
  McpServerOptions,
} from "@modelcontextprotocol/server";

import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import {
  FULL_CATALOG_IDENTITY,
  createCatalogIdentity,
} from "../catalogIdentity.js";
import {
  contractsForToolFamilies,
  toolFamilyId,
} from "../contracts/toolFamilies.js";
import { promptsForToolFamilies } from "../contracts/promptContracts.js";
import type { ToolResultDelivery } from "./toolResult.js";
import {
  EvidenceMcpServerCore,
  type CompactInputSchemaPresentation,
} from "./EvidenceMcpServerCore.js";

export {
  forgetPendingMcpRequest,
  type CompactInputSchemaPresentation,
} from "./EvidenceMcpServerCore.js";

/**
 * Identity whose digests cover exactly the contracts a registration advertises.
 * Composition reuses it when a deferred server attaches its runtime, so both
 * paths derive the same value from the same scope.
 */
export const catalogIdentityForToolFamilies = (
  compactPresentation: CompactInputSchemaPresentation | undefined,
  omitOutputSchemas: boolean,
  advertisedToolFamilies: ReadonlySet<string> | undefined,
): ReturnType<typeof createCatalogIdentity> =>
  compactPresentation === undefined &&
  !omitOutputSchemas &&
  advertisedToolFamilies === undefined
    ? FULL_CATALOG_IDENTITY
    : createCatalogIdentity({
        compactPresentation:
          compactPresentation === undefined
            ? undefined
            : { budgetBytes: compactPresentation.budgetBytes },
        contracts: contractsForToolFamilies(advertisedToolFamilies),
        outputSchemaProfile: omitOutputSchemas ? "off" : "full",
        promptContracts: promptsForToolFamilies(advertisedToolFamilies),
      });

/** Canonical composition retains the constructor's existing identity defaults. */
export class EvidenceMcpServer extends EvidenceMcpServerCore {
  constructor(
    info: Implementation,
    options: McpServerOptions,
    recordEvidence: EvidenceWriter["recordEvidence"] | undefined,
    delivery: ToolResultDelivery,
    compactPresentation: CompactInputSchemaPresentation | undefined = undefined,
    omitOutputSchemas = false,
    identity?: ReturnType<typeof createCatalogIdentity>,
    advertisedToolFamilies: ReadonlySet<string> | undefined = undefined,
  ) {
    super(
      info,
      options,
      recordEvidence,
      delivery,
      compactPresentation,
      omitOutputSchemas,
      identity ??
        catalogIdentityForToolFamilies(
          compactPresentation,
          omitOutputSchemas,
          advertisedToolFamilies,
        ),
      advertisedToolFamilies,
    );
  }

  /**
   * Out-of-scope tools stay registered but disabled: `tools/list` omits them
   * and calls fail with the SDK's disabled-tool error, so status reports
   * cannot direct agents to calls that always fail.
   */
  override advertisesTool(name: string): boolean {
    const families = this.advertisedToolFamilies;
    if (families === undefined) return true;
    const family = toolFamilyId(name);
    return family !== undefined && families.has(family);
  }
}
