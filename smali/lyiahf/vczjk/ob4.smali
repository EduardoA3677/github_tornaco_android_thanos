.class public final Llyiahf/vczjk/ob4;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# instance fields
.field public OooO:I

.field public final OooO0Oo:Llyiahf/vczjk/ob4;

.field public OooO0o:Llyiahf/vczjk/ob4;

.field public OooO0o0:Llyiahf/vczjk/ld9;

.field public OooO0oO:Ljava/lang/String;

.field public OooO0oo:Ljava/lang/Object;

.field public OooOO0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ob4;Llyiahf/vczjk/ld9;III)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/b23;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ob4;->OooO0Oo:Llyiahf/vczjk/ob4;

    iput-object p2, p0, Llyiahf/vczjk/ob4;->OooO0o0:Llyiahf/vczjk/ld9;

    iput p3, p0, Llyiahf/vczjk/b23;->OooO0O0:I

    iput p4, p0, Llyiahf/vczjk/ob4;->OooO:I

    iput p5, p0, Llyiahf/vczjk/ob4;->OooOO0:I

    const/4 p1, -0x1

    iput p1, p0, Llyiahf/vczjk/b23;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0oO:Ljava/lang/String;

    return-object v0
.end method

.method public final OooO0o()Llyiahf/vczjk/b23;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0Oo:Llyiahf/vczjk/ob4;

    return-object v0
.end method

.method public final OooO0o0()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0oo:Ljava/lang/Object;

    return-object v0
.end method

.method public final OooOO0(Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ob4;->OooO0oo:Ljava/lang/Object;

    return-void
.end method

.method public final OooOO0o(II)Llyiahf/vczjk/ob4;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0o:Llyiahf/vczjk/ob4;

    const/4 v1, 0x0

    if-nez v0, :cond_1

    new-instance v2, Llyiahf/vczjk/ob4;

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0o0:Llyiahf/vczjk/ld9;

    if-nez v0, :cond_0

    :goto_0
    move-object v4, v1

    goto :goto_1

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/ld9;->Oooo0O0()Llyiahf/vczjk/ld9;

    move-result-object v1

    goto :goto_0

    :goto_1
    const/4 v5, 0x1

    move-object v3, p0

    move v6, p1

    move v7, p2

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/ob4;-><init>(Llyiahf/vczjk/ob4;Llyiahf/vczjk/ld9;III)V

    iput-object v2, v3, Llyiahf/vczjk/ob4;->OooO0o:Llyiahf/vczjk/ob4;

    return-object v2

    :cond_1
    move-object v3, p0

    move v6, p1

    move v7, p2

    const/4 p1, 0x1

    iput p1, v0, Llyiahf/vczjk/b23;->OooO0O0:I

    const/4 p1, -0x1

    iput p1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    iput v6, v0, Llyiahf/vczjk/ob4;->OooO:I

    iput v7, v0, Llyiahf/vczjk/ob4;->OooOO0:I

    iput-object v1, v0, Llyiahf/vczjk/ob4;->OooO0oO:Ljava/lang/String;

    iput-object v1, v0, Llyiahf/vczjk/ob4;->OooO0oo:Ljava/lang/Object;

    iget-object p1, v0, Llyiahf/vczjk/ob4;->OooO0o0:Llyiahf/vczjk/ld9;

    if-eqz p1, :cond_2

    iput-object v1, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    iput-object v1, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    iput-object v1, p1, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    :cond_2
    return-object v0
.end method

.method public final OooOOO()Z
    .locals 3

    iget v0, p0, Llyiahf/vczjk/b23;->OooO0OO:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/b23;->OooO0OO:I

    iget v2, p0, Llyiahf/vczjk/b23;->OooO0O0:I

    if-eqz v2, :cond_0

    if-lez v0, :cond_0

    return v1

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOO0(II)Llyiahf/vczjk/ob4;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0o:Llyiahf/vczjk/ob4;

    const/4 v1, 0x0

    if-nez v0, :cond_1

    new-instance v2, Llyiahf/vczjk/ob4;

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0o0:Llyiahf/vczjk/ld9;

    if-nez v0, :cond_0

    :goto_0
    move-object v4, v1

    goto :goto_1

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/ld9;->Oooo0O0()Llyiahf/vczjk/ld9;

    move-result-object v1

    goto :goto_0

    :goto_1
    const/4 v5, 0x2

    move-object v3, p0

    move v6, p1

    move v7, p2

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/ob4;-><init>(Llyiahf/vczjk/ob4;Llyiahf/vczjk/ld9;III)V

    iput-object v2, v3, Llyiahf/vczjk/ob4;->OooO0o:Llyiahf/vczjk/ob4;

    return-object v2

    :cond_1
    move-object v3, p0

    move v6, p1

    move v7, p2

    const/4 p1, 0x2

    iput p1, v0, Llyiahf/vczjk/b23;->OooO0O0:I

    const/4 p1, -0x1

    iput p1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    iput v6, v0, Llyiahf/vczjk/ob4;->OooO:I

    iput v7, v0, Llyiahf/vczjk/ob4;->OooOO0:I

    iput-object v1, v0, Llyiahf/vczjk/ob4;->OooO0oO:Ljava/lang/String;

    iput-object v1, v0, Llyiahf/vczjk/ob4;->OooO0oo:Ljava/lang/Object;

    iget-object p1, v0, Llyiahf/vczjk/ob4;->OooO0o0:Llyiahf/vczjk/ld9;

    if-eqz p1, :cond_2

    iput-object v1, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    iput-object v1, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    iput-object v1, p1, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    :cond_2
    return-object v0
.end method

.method public final OooOOOO(Ljava/lang/String;)V
    .locals 4

    iput-object p1, p0, Llyiahf/vczjk/ob4;->OooO0oO:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/ob4;->OooO0o0:Llyiahf/vczjk/ld9;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ld9;->OoooOoO(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_1

    new-instance v1, Llyiahf/vczjk/bb4;

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/io/Closeable;

    instance-of v2, v0, Llyiahf/vczjk/eb4;

    if-eqz v2, :cond_0

    check-cast v0, Llyiahf/vczjk/eb4;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    const-string v2, "Duplicate field \'"

    const-string v3, "\'"

    invoke-static {v2, p1, v3}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/a69;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;)V

    throw v1

    :cond_1
    return-void
.end method
