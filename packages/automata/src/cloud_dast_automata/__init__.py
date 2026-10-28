"""Optional automata-learning extensions for Cloud DAST.

The implementation depends on AALpy and must not be imported while core is
only checking whether the plugin package exists.  Entry-point discovery can
therefore inspect this package without making AALpy a transitive core import.
"""

__all__ = ["AALpyAutomataLearningAdapter"]


def __getattr__(name: str):
    if name != "AALpyAutomataLearningAdapter":
        raise AttributeError(name)
    from cloud_dast_automata.learning import AALpyAutomataLearningAdapter

    return AALpyAutomataLearningAdapter
