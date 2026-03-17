import Foundation
import SwiftUI

/// Root application state, observable by all views.
@Observable
@MainActor
final class AppState {
    var coordinator = ScanCoordinator()
    let licenseManager = LicenseManager.shared

    /// The currently focused node for the sunburst display.
    var currentRoot: FileNode?

    /// Navigation stack for drill-down
    var navigationStack: [FileNode] = []

    /// Currently hovered node in the sunburst
    var hoveredNode: FileNode?

    /// Node selected via sidebar click — persists until cleared
    var selectedNode: FileNode?

    /// Items collected for potential deletion
    var collectorItems: [CollectorItem] = []

    /// O(1) node lookup by UUID — rebuilt after each scan/drill-down
    var nodeLookup: [UUID: FileNode] = [:]

    /// Whether to show the disk selector (welcome/home screen)
    var showDiskSelector: Bool = true

    /// Scan duration for display
    var lastScanDuration: TimeInterval?

    /// Panel visibility
    var showSidebar: Bool = true
    var showDetailPanel: Bool = true

    /// Whether to show the Pro upgrade sheet
    var showProUpgrade: Bool = false

    var scanRoot: FileNode? {
        navigationStack.first ?? currentRoot
    }

    func scan(path: String) {
        showDiskSelector = false
        navigationStack = []
        currentRoot = nil
        hoveredNode = nil
        lastScanDuration = nil
        coordinator.scan(path: path)
    }

    func onScanComplete() {
        if let root = coordinator.scanResult {
            // Assign colors once from the scan root — stable across drill-downs
            ColorAssigner.assignColors(root: root)
            currentRoot = root
            navigationStack = [root]
            lastScanDuration = coordinator.scanDuration
            rebuildNodeLookup(from: root)
        }
    }

    func drillDown(to node: FileNode) {
        guard node.isDirectory else { return }
        navigationStack.append(node)
        currentRoot = node
        hoveredNode = nil
        selectedNode = nil
    }

    func navigateUp() {
        guard navigationStack.count > 1 else { return }
        navigationStack.removeLast()
        currentRoot = navigationStack.last
        hoveredNode = nil
        selectedNode = nil
    }

    func navigateTo(index: Int) {
        guard index < navigationStack.count else { return }
        navigationStack = Array(navigationStack.prefix(index + 1))
        currentRoot = navigationStack.last
        hoveredNode = nil
        selectedNode = nil
    }

    /// Add a node to the collector
    func addToCollector(node: FileNode) {
        guard !collectorItems.contains(where: { $0.id == node.id }) else { return }
        collectorItems.append(CollectorItem(from: node))
    }

    /// Number of items that failed to delete in the last operation
    var lastDeleteFailCount: Int = 0

    /// Move all collector items to Trash (Pro feature)
    func deleteCollectorItems() {
        guard licenseManager.isPro else {
            showProUpgrade = true
            return
        }

        var deletedPaths: [String] = []
        var failedItems: [CollectorItem] = []

        for item in collectorItems {
            let url = URL(fileURLWithPath: item.path)
            do {
                try FileManager.default.trashItem(at: url, resultingItemURL: nil)
                deletedPaths.append(item.path)
            } catch {
                // Keep failed items in the collector so user can see what didn't work
                failedItems.append(item)
            }
        }

        // Only remove successfully deleted items; keep failures visible
        collectorItems = failedItems
        lastDeleteFailCount = failedItems.count

        // Re-scan to update the tree if we deleted anything
        if !deletedPaths.isEmpty, let root = scanRoot {
            scan(path: root.path)
        }
    }

    func goHome() {
        showDiskSelector = true
        currentRoot = nil
        navigationStack = []
        hoveredNode = nil
        coordinator.scanResult = nil
    }

    /// Resolve a dropped node ID string and add it to collector
    func collectNodeByID(_ idString: String) {
        guard let uuid = UUID(uuidString: idString),
              let node = nodeLookup[uuid] else { return }
        addToCollector(node: node)
    }

    /// Rebuild the O(1) lookup dictionary from a root node
    func rebuildNodeLookup(from root: FileNode) {
        var lookup: [UUID: FileNode] = [:]
        func walk(_ node: FileNode) {
            lookup[node.id] = node
            for child in node.children {
                walk(child)
            }
        }
        walk(root)
        nodeLookup = lookup
    }

    var canNavigateUp: Bool {
        navigationStack.count > 1
    }

    var breadcrumbs: [FileNode] {
        navigationStack
    }
}
