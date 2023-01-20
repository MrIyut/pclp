#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char good_domains[10][31] = {
	"123people.co.uk", "123people.com", "rootsweb.ancestry.com",
	"archiver.rootsweb.ancestry.com", "sports.espn.go.com",
	"vinoscalyptra.cl", "facebook.com", "edu.gov.on.ca",
	"bing.com", "google.com"
};

char GOOD_DOMAINS = 10;
char bad_domains[7][15] = {
	"pastebin.com", "poypal.com", "paipal.com",
	"chinesevie.com", "facebok.com", "facebooc.com", "facedooc.com"
};

char bad_tlds[43][8] = {
	".xyz", ".tk", ".ml", ".cf", ".icu", ".ga", ".adult", ".webcam",
	".top", ".pw", ".cn", ".gq", ".zw", ".bd", ".ke", ".pm", ".sbs", ".date",
	".quest", ".bid", ".win", ".casa", ".help", ".cyou", ".pw", ".am", ".cd",
	".ws", ".su", ".best", ".stream", ".uno", ".cm", ".cam", ".tokyo", ".club",
	".xxx", ".casino", ".poker", ".porn", ".bet", ".sex", ".sexy"
};

char bad_tlds_no = 43;

char UNALLOWED_EXTENSION[18][9] = {
	"exe", "sh", "bin", "mpsl",
	"ppc", "download", "arm7",
	"pdf", "css", "dat", "doc",
	"c", "py", "cpp",
	"pl", "jpg", "png", "bat"
};

char banned_extenstion = 18;
char allowed_extensions[3][4] = {"htm", "com", "do"};
char sus_elements[14][13] = {
	"v=ver", "#form", "/exe/", "/raw/",
	"args=", "server/", "=download", "host",
	"module=", "?environment", "&environment", ".ru.com",
	"wp-admin", "~"
};

int sus_elements_no = 14;
int MAX_LINK_SIZE = 75;
int MAX_F_IAT = 90000;
int CRYPTOMINER_RESPONSE_PORTS[3] = {137, 138, 1947};

char **read_file(size_t *size, FILE *file)
{
	char **array = malloc(sizeof(char *));
	if (!array) {
		perror("Unable to allocate memory");
		exit(1);
	}
	char *aux = NULL;
	size_t len = 0;

	while (getline(&aux, &len, file) != -1) {
		aux[strlen(aux) - 1] = '\0';
		char **test = realloc(array, (*size + 1) * sizeof(char *));
		if (test) {
			array = test;
		} else {
			free(aux);
			for (int i = 0; i < *(size); i++)
				free(array[i]);
			free(array);
			perror("Unable to reallocate memory!");
			exit(1);
		}

		array[*size] = calloc(strlen(aux) + 1, sizeof(char));
		memcpy(array[(*size)++], aux, strlen(aux));
		array[*size - 1][strlen(aux)] = '\0';
	}
	free(aux);
	fclose(file);
	return array;
}

int is_in_database(char *domain, char **urls_db, size_t db_size)
{
	for (int i = 0; i < db_size; i++)
		if (strcmp(domain, urls_db[i]) == 0)
			return 1;

	for (int i = 0; i < 7; i++)
		if (strcmp(domain, bad_domains[i]) == 0)
			return 1;
	return 0;
}

int is_unallowed_extension(char *extension)
{
	for (int i = 0; i < banned_extenstion; i++)
		if (strcmp(extension, UNALLOWED_EXTENSION[i]) == 0)
			return 1;
	return 0;
}

int has_sus_elem(char *link)
{
	for (int i = 0; i < sus_elements_no; i++)
		if (strstr(link, sus_elements[i]))
			return 1;

	return 0;
}

int good_extension(char *extension)
{
	for (int i = 0; i < 3; i++)
		if (strstr(extension, allowed_extensions[i]))
			return 1;

	return 0;
}

int trusted_domain(char *domain)
{
	for (int i = 0; i < GOOD_DOMAINS; i++)
		if (strcmp(domain, good_domains[i]) == 0)
			return 1;
	return 0;
}

char *get_last_part(char *str, char *del)
{
	char *last_part = strtok(str, del);
	char *part = strtok(NULL, del);
	while (part) {
		last_part = part;
		part = strtok(NULL, del);
	}
	last_part[strlen(last_part)] = '\0';
	return last_part;
}

int can_be_bad_domain(char *domain)
{
	for (int i = 0; i < bad_tlds_no; i++) {
		char *found = strstr(domain, bad_tlds[i]);
		int len = strlen(bad_tlds[i]);
		if (found && (found[len] == '\0' || found[len] == '/'))
			return 1;
	}
	if (strstr(domain, ".edu"))
		return 0;

	int part_counts = 0;
	char *part = strtok(domain, ".");
	if (!part)
		return 1;
	if (strlen(part) > 32)
		return 1;

	if (strstr(part, "www") && strcmp(part, "www") != 0)
		return 1;

	if (strcmp(part, "m") == 0)
		part_counts -= 1;

	while (part) {
		part_counts += 1;
		part = strtok(NULL, ".");
	}

	if (part_counts > 3)
		return 1;
}

char *get_last_occurence(char *string, char del, int return_null)
{
	char *occurence = NULL;
	for (int i = strlen(string) - 1; i >= 0; i--)
		if (string[i] == del) {
			occurence = string + i + 1;
			return occurence;
		}

	if (return_null)
		return NULL;
	occurence = string;
	return occurence;
}

char *get_first_occurence(char *string, char del)
{
	char *occurence = NULL;
	for (int i = 0; i < strlen(string) - 1; i++)
		if (string[i] == del) {
			occurence = string + i;
			return occurence;
		}

	return occurence;
}

int too_many_subdomains(char *domain)
{
	int count = 0;
	for (int i = 0; i < strlen(domain); i++)
		if (domain[i] == '.')
			count += 1;

	if (count > 5)
		return 1;

	return 0;
}

void decide_is_not_gud(char *link, char **urls_db, size_t db_size, FILE *output)
{
	char *test_link = strdup(link);
	char *copy_link = strdup(link);
	char *last_part = get_last_part(link, "/");
	char *extension = get_last_occurence(last_part, '.', 0);
	char *frag_hash = get_last_occurence(last_part, '#', 1);
	char *file = get_first_occurence(last_part, '?');
	char last_char = test_link[strlen(test_link) - 1];
	char *domain = strtok(test_link, "/");

	int empty_var = strstr(link, "=&") && !strstr(link, "==&");
	int many_comps = too_many_subdomains(domain);
	int is_trusted_domain = trusted_domain(domain);
	int no_var = (last_char == '=' || (frag_hash && !strchr(frag_hash, '=')));
	int too_long_file_name = (file && file - last_part > 63);
	int just_domain = (strcmp(last_part, domain) == 0 && last_char != '/');
	int has_sus_parts = (has_sus_elem(copy_link) && !good_extension(extension));
	int unallowed_file_type = is_unallowed_extension(extension);
	int known_bad_url = is_in_database(domain, urls_db, db_size);
	int bad_domain = can_be_bad_domain(domain);
	int url_starts_with_digit = domain[0] >= '0' && domain[0] <= '9';

	free(copy_link);
	free(test_link);

	if (is_trusted_domain) {
		fprintf(output, "0\n");
		return;
	}
	if (bad_domain || url_starts_with_digit || empty_var) {
		fprintf(output, "1\n");
		return;
	}
	if (just_domain || too_long_file_name || no_var) {
		fprintf(output, "1\n");
		return;
	}
	if (has_sus_parts || unallowed_file_type || known_bad_url) {
		fprintf(output, "1\n");
		return;
	}
	if (many_comps) {
		fprintf(output, "1\n");
		return;
	}

	fprintf(output, "0\n");
}

int known_safe(char *link, char **safe_domains, size_t safe_domains_no)
{
	char *test_link = strdup(link);
	char *domain = strtok(test_link, "/");

	for (int i = 0; i < safe_domains_no; i++)
		if (strcmp(domain, safe_domains[i]) == 0) {
			free(test_link);
			return 1;
		}

	free(test_link);
	return 0;
}

void task1(void)
{
	FILE *output_task1, *input_task1, *database, *safe_domains_file;
	output_task1 = fopen("urls-predictions.out", "w");
	input_task1 = fopen("./data/urls/urls.in", "r");
	database = fopen("./data/urls/domains_database", "r");
	safe_domains_file = fopen("data.txt", "r");

	if (!input_task1 || !output_task1) {
		perror("Unable to open file!");
		exit(1);
	}

	char **urls_db = NULL, **safe_domains = NULL;
	char *link = NULL;
	size_t len = 0, database_size = 0, safe_domains_no = 0;
	urls_db = read_file(&database_size, database);
	safe_domains = read_file(&safe_domains_no, safe_domains_file);
	while (getline(&link, &len, input_task1) != -1) {
		link[strlen(link) - 1] = '\0';
		int is_known_safe = known_safe(link, safe_domains, safe_domains_no);
		if (is_known_safe)
			fprintf(output_task1, "0\n");
		else
			decide_is_not_gud(link, urls_db, database_size, output_task1);
	}

	fclose(output_task1);
	fclose(input_task1);

	free(link);
	for (int i = 0; i < database_size; i++)
		free(urls_db[i]);
	free(urls_db);

	for (int i = 0; i < safe_domains_no; i++)
		free(safe_domains[i]);
	free(safe_domains);
}

char **get_elements(char *str, char *del, int *elem_no)
{
	char **elements = malloc(sizeof(char *));
	if (!elements) {
		perror("Unable to allocate memory");
		exit(1);
	}

	char *element = strtok(str, del);
	while (element) {
		char **aux = realloc(elements, (*elem_no + 1) * sizeof(char *));
		if (aux) {
			elements = aux;
		} else {
			perror("Unable to allocate memory");
			exit(1);
		}

		elements[*elem_no] = calloc(strlen(element) + 1, sizeof(char));
		strcpy(elements[(*elem_no)++], element);
		elements[*elem_no - 1][strlen(element)] = '\0';

		element = strtok(NULL, del);
	}
	free(element);
	return elements;
}

int is_long_flow_duration(char **flow_duration)
{
	if (flow_duration[2][7] > '0')
		return 1;
	if (flow_duration[2][7] == '0' && flow_duration[2][8] == '.') // >=0.97 sec
		if (flow_duration[2][9] == '9' && flow_duration[2][10] >= '7')
			return 1;
	return 0;
}

void analyze_traffic(char **traffic, int elem_no, FILE *output)
{
	int comp_no = 0, ip_elem1 = 0, ip_elem2 = 0;
	char **flow_duration = get_elements(traffic[4], " ", &comp_no);
	char *extraptr = NULL;
	double flow_dur = strtod(flow_duration[2] + 7, &extraptr);
	int long_flow_duration = is_long_flow_duration(flow_duration);
	int avg_pay0 = strcmp(traffic[elem_no - 1], "0.0") == 0;
	int approx_zero_duration = flow_dur < 0.001;
	size_t fwd_header_size_tot = atoi(traffic[8]);
	int high_fwd_header_size = fwd_header_size_tot > 1000;
	double fwd_iat_avg = strtod(traffic[14], &extraptr);
	char **origin_ip = get_elements(traffic[0], ".", &ip_elem1);
	char **response_ip = get_elements(traffic[2], ".", &ip_elem2);
	int flow_ACK_flag_count = atoi(traffic[11]);
	int same_network = 1;
	for (int i = 0; i < 2; i++)
		if (strcmp(origin_ip[i], response_ip[i]) != 0) {
			same_network = 0;
			break;
		}
	int response_port = atoi(traffic[3]);
	int miner_port = 0;
	for (int i = 0; i < 3; i++)
		if (response_port == CRYPTOMINER_RESPONSE_PORTS[i]) {
			miner_port = 1;
			break;
		}

	for (int i = 0; i < comp_no; i++)
		free(flow_duration[i]);
	free(flow_duration);
	for (int i = 0; i < ip_elem1; i++)
		free(origin_ip[i]);
	free(origin_ip);
	for (int i = 0; i < ip_elem2; i++)
		free(response_ip[i]);
	free(response_ip);

	if (approx_zero_duration && same_network && miner_port) {
		if (!avg_pay0) {
			fprintf(output, "1\n");
			return;
		}
	} else {
		if (!avg_pay0 && flow_dur != (double)0 && fwd_iat_avg != (double)0) {
			double value = fwd_iat_avg / flow_dur;
			if (value > MAX_F_IAT && same_network && miner_port) {
				fprintf(output, "1\n");
				return;
			}
		}
	}

	int high_traffic = (long_flow_duration || flow_ACK_flag_count >= 75);
	if (high_traffic && !avg_pay0 && high_fwd_header_size) {
		fprintf(output, "1\n");
		return;
	}

	fprintf(output, "0\n");
}

void task2(void)
{
	FILE *output_task2, *input_task2;
	output_task2 = fopen("traffic-predictions.out", "w");
	input_task2 = fopen("./data/traffic/traffic.in", "r");
	if (!input_task2 || !output_task2) {
		perror("Unable to open file!");
		exit(1);
	}

	char *traffic = NULL;
	size_t len = 0;
	getline(&traffic, &len, input_task2);
	while (getline(&traffic, &len, input_task2) != -1) {
		traffic[strlen(traffic) - 1] = '\0';
		int elem_no = 0;
		char **elements = get_elements(traffic, ",", &elem_no);
		analyze_traffic(elements, elem_no, output_task2);
		for (int i = 0; i < elem_no; i++)
			free(elements[i]);
		free(elements);
	}

	free(traffic);
	fclose(output_task2);
	fclose(input_task2);
}

int main(void)
{
	task1();
	task2();
	return 0;
}