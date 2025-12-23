.class public final Llyiahf/vczjk/qw4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ru4;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/er4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/er4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qw4;->OooO00o:Llyiahf/vczjk/er4;

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/qw4;->OooO00o:Llyiahf/vczjk/er4;

    invoke-virtual {v0}, Llyiahf/vczjk/er4;->OooO0oO()Llyiahf/vczjk/oq4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/oq4;->OooOOo0:Llyiahf/vczjk/nf6;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v1, v2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/er4;->OooO0oO()Llyiahf/vczjk/oq4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/oq4;->OooO0o0()J

    move-result-wide v0

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    :goto_0
    long-to-int v0, v0

    return v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/er4;->OooO0oO()Llyiahf/vczjk/oq4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/oq4;->OooO0o0()J

    move-result-wide v0

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    goto :goto_0
.end method

.method public final OooO0O0()F
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qw4;->OooO00o:Llyiahf/vczjk/er4;

    iget-object v1, v0, Llyiahf/vczjk/er4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v1}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v1

    iget-object v0, v0, Llyiahf/vczjk/er4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v0}, Llyiahf/vczjk/tq4;->OooO0O0()I

    move-result v0

    mul-int/lit16 v1, v1, 0x1f4

    add-int/2addr v1, v0

    int-to-float v0, v1

    return v0
.end method

.method public final OooO0OO()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qw4;->OooO00o:Llyiahf/vczjk/er4;

    invoke-virtual {v0}, Llyiahf/vczjk/er4;->OooO0oO()Llyiahf/vczjk/oq4;

    move-result-object v1

    iget v1, v1, Llyiahf/vczjk/oq4;->OooOOO0:I

    neg-int v1, v1

    invoke-virtual {v0}, Llyiahf/vczjk/er4;->OooO0oO()Llyiahf/vczjk/oq4;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/oq4;->OooOOo:I

    add-int/2addr v1, v0

    return v1
.end method

.method public final OooO0Oo()F
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/qw4;->OooO00o:Llyiahf/vczjk/er4;

    iget-object v1, v0, Llyiahf/vczjk/er4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v1}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v1

    iget-object v2, v0, Llyiahf/vczjk/er4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v2}, Llyiahf/vczjk/tq4;->OooO0O0()I

    move-result v2

    invoke-virtual {v0}, Llyiahf/vczjk/er4;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_0

    mul-int/lit16 v1, v1, 0x1f4

    add-int/2addr v1, v2

    int-to-float v0, v1

    const/16 v1, 0x64

    int-to-float v1, v1

    add-float/2addr v0, v1

    return v0

    :cond_0
    mul-int/lit16 v1, v1, 0x1f4

    add-int/2addr v1, v2

    int-to-float v0, v1

    return v0
.end method

.method public final OooO0o()Llyiahf/vczjk/v11;
    .locals 2

    new-instance v0, Llyiahf/vczjk/v11;

    const/4 v1, -0x1

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/v11;-><init>(II)V

    return-object v0
.end method

.method public final OooO0o0(ILlyiahf/vczjk/xu4;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/er4;->OooOo0o:Llyiahf/vczjk/era;

    iget-object v0, p0, Llyiahf/vczjk/qw4;->OooO00o:Llyiahf/vczjk/er4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/cr4;

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-direct {v1, v0, p1, v3, v2}, Llyiahf/vczjk/cr4;-><init>(Llyiahf/vczjk/er4;IILlyiahf/vczjk/yo1;)V

    sget-object p1, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    invoke-virtual {v0, p1, v1, p2}, Llyiahf/vczjk/er4;->OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-ne p1, p2, :cond_1

    return-object p1

    :cond_1
    return-object v0
.end method
