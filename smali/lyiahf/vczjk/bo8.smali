.class public final Llyiahf/vczjk/bo8;
.super Llyiahf/vczjk/eb0;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/yn;

.field public final OooOOOO:Llyiahf/vczjk/pm;

.field public final OooOOOo:Llyiahf/vczjk/wa7;

.field public final OooOOo:Llyiahf/vczjk/fa4;

.field public final OooOOo0:Llyiahf/vczjk/xa7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/pm;Llyiahf/vczjk/xa7;Llyiahf/vczjk/wa7;Llyiahf/vczjk/fa4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bo8;->OooOOO:Llyiahf/vczjk/yn;

    iput-object p2, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    iput-object p3, p0, Llyiahf/vczjk/bo8;->OooOOo0:Llyiahf/vczjk/xa7;

    if-nez p4, :cond_0

    sget-object p4, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    :cond_0
    iput-object p4, p0, Llyiahf/vczjk/bo8;->OooOOOo:Llyiahf/vczjk/wa7;

    iput-object p5, p0, Llyiahf/vczjk/bo8;->OooOOo:Llyiahf/vczjk/fa4;

    return-void
.end method

.method public static OooOoOO(Llyiahf/vczjk/gg8;Llyiahf/vczjk/qja;Llyiahf/vczjk/xa7;Llyiahf/vczjk/wa7;Llyiahf/vczjk/ea4;)Llyiahf/vczjk/bo8;
    .locals 7

    if-eqz p4, :cond_2

    sget-object v0, Llyiahf/vczjk/ea4;->OooOOo0:Llyiahf/vczjk/ea4;

    if-ne p4, v0, :cond_0

    goto :goto_1

    :cond_0
    sget-object v1, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    if-eq p4, v0, :cond_1

    new-instance v0, Llyiahf/vczjk/fa4;

    const/4 v1, 0x0

    invoke-direct {v0, p4, v1, v1, v1}, Llyiahf/vczjk/fa4;-><init>(Llyiahf/vczjk/ea4;Llyiahf/vczjk/ea4;Ljava/lang/Class;Ljava/lang/Class;)V

    goto :goto_0

    :cond_1
    sget-object v0, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    :goto_0
    move-object v6, v0

    goto :goto_2

    :cond_2
    :goto_1
    sget-object v0, Llyiahf/vczjk/eb0;->OooOOO0:Llyiahf/vczjk/fa4;

    goto :goto_0

    :goto_2
    new-instance v1, Llyiahf/vczjk/bo8;

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v2

    move-object v3, p1

    move-object v4, p2

    move-object v5, p3

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/bo8;-><init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/pm;Llyiahf/vczjk/xa7;Llyiahf/vczjk/wa7;Llyiahf/vczjk/fa4;)V

    return-object v1
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/wa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOo:Llyiahf/vczjk/wa7;

    return-object v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/fa4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOo:Llyiahf/vczjk/fa4;

    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/vm;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    instance-of v1, v0, Llyiahf/vczjk/vm;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/vm;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOOO()Llyiahf/vczjk/mm;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    instance-of v1, v0, Llyiahf/vczjk/mm;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/mm;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOOO0()Ljava/util/Iterator;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/bo8;->OooOO0o()Llyiahf/vczjk/vm;

    move-result-object v0

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/vy0;->OooO0OO:Ljava/util/Iterator;

    return-object v0

    :cond_0
    invoke-static {v0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOOO()Llyiahf/vczjk/rm;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    instance-of v1, v0, Llyiahf/vczjk/rm;

    if-eqz v1, :cond_0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/rm;

    invoke-virtual {v1}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v1

    array-length v1, v1

    if-nez v1, :cond_0

    check-cast v0, Llyiahf/vczjk/rm;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOOOo()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    if-nez v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOo()Llyiahf/vczjk/rm;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    instance-of v1, v0, Llyiahf/vczjk/rm;

    if-eqz v1, :cond_0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/rm;

    invoke-virtual {v1}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v1

    array-length v1, v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    check-cast v0, Llyiahf/vczjk/rm;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOOo0()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    if-nez v0, :cond_0

    const-class v0, Ljava/lang/Object;

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/u34;->OooOoOO()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOoo()Llyiahf/vczjk/xa7;
    .locals 3

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/bo8;->OooOOO:Llyiahf/vczjk/yn;

    if-eqz v1, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1
    :goto_0
    return-object v0
.end method

.method public final OooOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    instance-of v0, v0, Llyiahf/vczjk/mm;

    return v0
.end method

.method public final OooOo00()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOOO:Llyiahf/vczjk/pm;

    instance-of v0, v0, Llyiahf/vczjk/vm;

    return v0
.end method

.method public final OooOo0O(Llyiahf/vczjk/xa7;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOo0:Llyiahf/vczjk/xa7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xa7;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final OooOo0o()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/bo8;->OooOOo()Llyiahf/vczjk/rm;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoO0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final getFullName()Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOo0:Llyiahf/vczjk/xa7;

    return-object v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bo8;->OooOOo0:Llyiahf/vczjk/xa7;

    invoke-virtual {v0}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
