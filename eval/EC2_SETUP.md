# EC2 GPU training setup for redasq GLiNER fine-tuning

## Recommended instance

| Instance | GPU | vCPU | RAM | $/hr | Notes |
|---|---|---|---|---|---|
| `g5.xlarge` | 1× A10G (24GB) | 4 | 16GB | ~$1.00 | **Recommended** — fast, cheap, plenty of memory |
| `g4dn.xlarge` | 1× T4 (16GB) | 4 | 16GB | ~$0.53 | Cheaper, slower |
| `p3.2xlarge` | 1× V100 (16GB) | 8 | 61GB | ~$3.06 | Overkill for this size |

For 23K examples × 5 epochs, expect **5-15 min training time** on g5.xlarge.

## AMI

Use **Deep Learning AMI (Ubuntu 22.04)** — comes with CUDA, PyTorch, and conda pre-installed.
Search AWS console → "Deep Learning AMI GPU PyTorch".

## Quick setup script (run on the EC2 instance after SSH)

```bash
# 1. Activate the pre-installed pytorch env
source activate pytorch

# 2. Install GLiNER + dependencies
pip install gliner exrex

# 3. Pull training data + scripts (or scp them up — see below)
mkdir -p ~/redasq && cd ~/redasq

# 4. Train (assuming files are uploaded)
python train_gliner.py
```

## Upload from local

From your local Mac, after the EC2 instance is up:

```bash
# Replace with your instance details
INSTANCE=ubuntu@<ec2-public-ip>
KEY=~/.ssh/your-ec2-key.pem

# Upload training data + scripts
scp -i $KEY \
  training_data.json \
  train_gliner.py \
  $INSTANCE:~/redasq/

# After training, download the fine-tuned model
scp -i $KEY -r $INSTANCE:~/redasq/gliner_redasq ./
```

## Cost estimate

- Setup + training: ~30 min on g5.xlarge = **~$0.50**
- Iterate 10× while tuning: **~$5**

Stop the instance when done (`aws ec2 stop-instances --instance-ids ...`) — you only pay for running time + EBS storage.
