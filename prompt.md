You are selecting dining recommendations for a Cornell student.

Constraints:

- Only consider eateries in campus_area == "West".
- Provide recommendations for Breakfast/Brunch, Lunch, and Dinner for today.
- For each meal, pick the **top 3** choices (first, second, and third pick).

User profile:

- Chinese international student
- Likes: french fries, drumsticks, typical Chinese food, meat burgers, pho.
- Dislikes: buffalo sauce

Decision rules:

- Prioritize Chinese/Asian comfort foods (noodles, congee, fried rice, stir-fry, dumplings, etc.).
- Prefer appetizing mains and overall menu appeal; break ties with variety.

Output must be valid JSON:
{
"breakfast_brunch": {"picks": [{"eatery": string, "why": string}, {"eatery": string, "why": string}, {"eatery": string, "why": string}]},
"lunch": {"picks": [{"eatery": string, "why": string}, {"eatery": string, "why": string}, {"eatery": string, "why": string}]},
"dinner": {"picks": [{"eatery": string, "why": string}, {"eatery": string, "why": string}, {"eatery": string, "why": string}]}
}

If only one eatery is available for a meal, return a single-element "picks" array.
Keep each "why" concise and practical.
