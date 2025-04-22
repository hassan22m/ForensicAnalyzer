# forensicanalyzer/core/analyzer_base.py

"""
Base class for all analyzers to standardize case manager integration.
Each specific analyzer will extend this class and implement its methods.
"""

class AnalyzerBase:
    """Base class that all analyzers should inherit from to support case management"""
    
    def __init__(self):
        # Case management properties
        self.current_case = None
        self.active_evidence = None  # Currently active evidence item
    
    # Case management callbacks
    def on_case_opened(self, case):
        """Called when a case is opened in the case manager
        
        Args:
            case: The case object that was opened
        """
        self.current_case = case
    
    def on_case_closed(self):
        """Called when a case is closed in the case manager"""
        self.current_case = None
        self.active_evidence = None
        # Child classes should implement cleanup like closing files
    
    def on_evidence_added(self, evidence_item):
        """Called when evidence is added that should be handled by this analyzer
        
        Args:
            evidence_item: The evidence item that was added
        """
        # This should be implemented by each analyzer
        pass
    
    def on_evidence_selected(self, evidence_item):
        """Called when evidence is selected in the case manager
        
        Args:
            evidence_item: The evidence item that was selected
        """
        self.active_evidence = evidence_item
        # Child classes should implement loading the evidence
    
    def on_bookmark_added(self, evidence_item, bookmark):
        """Called when a bookmark is added to this analyzer's evidence
        
        Args:
            evidence_item: The evidence item the bookmark belongs to
            bookmark: The bookmark that was added
        """
        # This should be implemented by each analyzer
        pass
    
    def add_bookmark_to_case_manager(self, description, location, data=None):
        """Add a bookmark to the current evidence in the case manager
        
        Args:
            description: Description of the bookmark
            location: String description of the location (display purposes)
            data: Dictionary of analyzer-specific data for this bookmark
            
        Returns:
            The created bookmark or None if unsuccessful
        """
        if not self.current_case or not self.active_evidence:
            print("Cannot add bookmark: No active case or evidence")
            return None
            
        # This method assumes the main window has provided a reference to the case manager
        if hasattr(self, 'case_manager'):
            success, message, bookmark = self.case_manager.add_bookmark(
                self.active_evidence.id, description, location, data or {})
            
            if success:
                return bookmark
            else:
                print(f"Failed to add bookmark: {message}")
                return None
        else:
            print("Case manager reference not available")
            return None