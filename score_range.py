'''
Set Score Ranges
'''
class ScoreRange:
    def __init__(self, min_threat=0, max_threat=100, min_certainty=0, max_certainty=100):
        self.min_threat = min_threat
        self.max_threat = max_threat
        self.min_certainty = min_certainty
        self.max_certainty = max_certainty

    def in_range(self, threat, certainty):
        return (
            threat >= self.min_threat
            and threat <= self.max_threat
            and certainty >= self.min_certainty
            and certainty <= self.max_certainty
        )

LOW = ScoreRange(
    min_threat=0,
    max_threat=50,
    min_certainty=0,
    max_certainty=50
)
MEDIUM = ScoreRange(
    min_threat=0,
    max_threat=50,
    min_certainty=50,
    max_certainty=100
)
HIGH = ScoreRange(
    min_threat=50,
    max_threat=100,
    min_certainty=0,
    max_certainty=50
)
CRITICAL = ScoreRange(
    min_threat=50,
    max_threat=100,
    min_certainty=50,
    max_certainty=100
)
