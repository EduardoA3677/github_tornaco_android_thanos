.class public final Llyiahf/vczjk/g0a;
.super Llyiahf/vczjk/hg8;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/k87;

.field public final OooO0O0:Llyiahf/vczjk/nk3;

.field public final OooO0OO:Lcom/google/gson/reflect/TypeToken;

.field public final OooO0Oo:Llyiahf/vczjk/s1a;

.field public final OooO0o:Z

.field public final OooO0o0:Llyiahf/vczjk/as7;

.field public volatile OooO0oO:Llyiahf/vczjk/r1a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k87;Llyiahf/vczjk/nk3;Lcom/google/gson/reflect/TypeToken;Llyiahf/vczjk/s1a;Z)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/hg8;-><init>()V

    new-instance v0, Llyiahf/vczjk/as7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/as7;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/g0a;->OooO0o0:Llyiahf/vczjk/as7;

    iput-object p1, p0, Llyiahf/vczjk/g0a;->OooO00o:Llyiahf/vczjk/k87;

    iput-object p2, p0, Llyiahf/vczjk/g0a;->OooO0O0:Llyiahf/vczjk/nk3;

    iput-object p3, p0, Llyiahf/vczjk/g0a;->OooO0OO:Lcom/google/gson/reflect/TypeToken;

    iput-object p4, p0, Llyiahf/vczjk/g0a;->OooO0Oo:Llyiahf/vczjk/s1a;

    iput-boolean p5, p0, Llyiahf/vczjk/g0a;->OooO0o:Z

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0oO:Llyiahf/vczjk/r1a;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0O0:Llyiahf/vczjk/nk3;

    iget-object v1, p0, Llyiahf/vczjk/g0a;->OooO0Oo:Llyiahf/vczjk/s1a;

    iget-object v2, p0, Llyiahf/vczjk/g0a;->OooO0OO:Lcom/google/gson/reflect/TypeToken;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/nk3;->OooO0o(Llyiahf/vczjk/s1a;Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/g0a;->OooO0oO:Llyiahf/vczjk/r1a;

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/r1a;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO00o:Llyiahf/vczjk/k87;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0oO:Llyiahf/vczjk/r1a;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0O0:Llyiahf/vczjk/nk3;

    iget-object v1, p0, Llyiahf/vczjk/g0a;->OooO0Oo:Llyiahf/vczjk/s1a;

    iget-object v2, p0, Llyiahf/vczjk/g0a;->OooO0OO:Lcom/google/gson/reflect/TypeToken;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/nk3;->OooO0o(Llyiahf/vczjk/s1a;Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/g0a;->OooO0oO:Llyiahf/vczjk/r1a;

    :cond_0
    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/r1a;->OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V

    return-void

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/g0a;->OooO0o:Z

    if-eqz v0, :cond_2

    if-nez p2, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OoooO00()Llyiahf/vczjk/zc4;

    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0OO:Lcom/google/gson/reflect/TypeToken;

    invoke-virtual {v0}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v0

    check-cast p2, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;

    const-string v1, "src"

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "typeOfSrc"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0o0:Llyiahf/vczjk/as7;

    const-string v1, "context"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/wa4;

    invoke-direct {v1}, Llyiahf/vczjk/wa4;-><init>()V

    invoke-virtual {p2}, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/as7;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/g94;

    move-result-object v2

    const-string v3, "name"

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/wa4;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/g94;)V

    invoke-virtual {p2}, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;->getDescription()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/as7;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/g94;

    move-result-object v2

    const-string v3, "description"

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/wa4;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/g94;)V

    invoke-virtual {p2}, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;->getPriority()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/as7;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/g94;

    move-result-object v2

    const-string v3, "priority"

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/wa4;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/g94;)V

    invoke-virtual {p2}, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;->getDelay()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/as7;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/g94;

    move-result-object v2

    const-string v3, "delay"

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/wa4;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/g94;)V

    invoke-virtual {p2}, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;->getCondition()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/as7;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/g94;

    move-result-object v2

    const-string v3, "condition"

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/wa4;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/g94;)V

    invoke-virtual {p2}, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;->getActions()Ljava/util/List;

    move-result-object p2

    invoke-virtual {v0, p2}, Llyiahf/vczjk/as7;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/g94;

    move-result-object p2

    const-string v0, "actions"

    invoke-virtual {v1, v0, p2}, Llyiahf/vczjk/wa4;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/g94;)V

    sget-object p2, Llyiahf/vczjk/x2a;->OooOoO:Llyiahf/vczjk/h94;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, p1}, Llyiahf/vczjk/h94;->OooO0o0(Llyiahf/vczjk/g94;Llyiahf/vczjk/zc4;)V

    return-void
.end method

.method public final OooO0Oo()Llyiahf/vczjk/r1a;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO00o:Llyiahf/vczjk/k87;

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0oO:Llyiahf/vczjk/r1a;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/g0a;->OooO0O0:Llyiahf/vczjk/nk3;

    iget-object v1, p0, Llyiahf/vczjk/g0a;->OooO0Oo:Llyiahf/vczjk/s1a;

    iget-object v2, p0, Llyiahf/vczjk/g0a;->OooO0OO:Lcom/google/gson/reflect/TypeToken;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/nk3;->OooO0o(Llyiahf/vczjk/s1a;Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/g0a;->OooO0oO:Llyiahf/vczjk/r1a;

    :cond_1
    return-object v0
.end method
