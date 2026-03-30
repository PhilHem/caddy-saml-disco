package domain

// SeparatePinnedIdPs separates configured pinned IdPs from the main list.
// Returns (pinnedIdPs, remainingIdPs). Pinned IdPs are returned in the order
// specified in the configuration, not in their original order in the list.
//
// This is a pure function that contains no I/O or external dependencies.
func SeparatePinnedIdPs(idps []IdPInfo, pinnedEntityIDs []string) (pinned, remaining []IdPInfo) {
	if len(pinnedEntityIDs) == 0 {
		return []IdPInfo{}, idps
	}

	// Create a map for quick lookup of pinned entity IDs
	pinnedSet := make(map[string]bool, len(pinnedEntityIDs))
	for _, entityID := range pinnedEntityIDs {
		pinnedSet[entityID] = true
	}

	// Create a map to look up IdP info by entity ID
	idpMap := make(map[string]IdPInfo, len(idps))
	for _, idp := range idps {
		idpMap[idp.EntityID] = idp
	}

	// Build pinned list in configuration order
	pinned = make([]IdPInfo, 0, len(pinnedEntityIDs))
	for _, entityID := range pinnedEntityIDs {
		if idp, ok := idpMap[entityID]; ok {
			pinned = append(pinned, idp)
		}
	}

	// Build remaining list (excluding pinned)
	remaining = make([]IdPInfo, 0, len(idps))
	for _, idp := range idps {
		if !pinnedSet[idp.EntityID] {
			remaining = append(remaining, idp)
		}
	}

	return pinned, remaining
}
