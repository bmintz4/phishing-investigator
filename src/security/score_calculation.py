


## Percentage of score that is taken from the ML model
ML_WEIGHT_RATIO = .20
URL_WEIGHT_RATIO = .10

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


def risk_rating_url(rules: list[dict], ml_score: int, url_reputation: list[dict]):
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
    

    ## calculate URL risk score based on VirusTotal API results
    url_score_max = 0
    worst_url = None
    for url in url_reputation:
        if url["last analysis stats"] is None:
            continue
        malicious = url["last analysis stats"]["malicious"]
        suspicious = url["last analysis stats"]["suspicious"]
        harmless = url["last analysis stats"]["harmless"]
        url_score = round((malicious * 2 + suspicious) / (harmless + malicious + suspicious if harmless + malicious + suspicious else 1) * 100)
        if url_score > url_score_max:
            url_score_max = url_score
            worst_url = url["URL"]

    if url_score_max > 100:
        url_score_max = 100

    ## combine manual rule score and ML score
    return ml_score * ML_WEIGHT_RATIO + url_score_max * URL_WEIGHT_RATIO + rule_risk * (1 - ML_WEIGHT_RATIO - URL_WEIGHT_RATIO), rule_risk, url_score_max, worst_url