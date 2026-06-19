


## Percentage of score that is taken from the ML model
ML_WEIGHT_RATIO = .20

## calculate overall risk rating
def risk_rating(rules: list[dict], ml_score: int):
    ## count each type of alert up to two times, separated based on severity
    high_count, med_count, low_count = 0, 0, 0
    rule_tracker = {}
    for rule in rules:
        if rule["subtype"] not in rule_tracker or rule_tracker[rule["subtype"]] == 1:
            match rule["severity"]:
                case "high":
                    high_count += 1
                case "medium":
                    med_count += 1
                case "low":
                    low_count += 1
            if rule["subtype"] not in rule_tracker:
                rule_tracker[rule["subtype"]] = 1
            else:
                rule_tracker[rule["subtype"]] = 2
            
## add the counts multiplied by weight based on severity, up to 100 
    rule_risk = high_count * 25 + med_count * 15 + low_count * 5
    if rule_risk > 100:
        rule_risk = 100

## combine manual rule score and ML score
    return ml_score * ML_WEIGHT_RATIO + rule_risk * (1 - ML_WEIGHT_RATIO), rule_risk