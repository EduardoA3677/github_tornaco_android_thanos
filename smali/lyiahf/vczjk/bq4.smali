.class public final Llyiahf/vczjk/bq4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nt4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/er4;

.field public final OooO0O0:Llyiahf/vczjk/zp4;

.field public final OooO0OO:Llyiahf/vczjk/uy5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/er4;Llyiahf/vczjk/zp4;Llyiahf/vczjk/uy5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bq4;->OooO00o:Llyiahf/vczjk/er4;

    iput-object p2, p0, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    iput-object p3, p0, Llyiahf/vczjk/bq4;->OooO0OO:Llyiahf/vczjk/uy5;

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    invoke-virtual {v0}, Llyiahf/vczjk/zp4;->OooO0O0()Llyiahf/vczjk/yw;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/yw;->OooO0O0:I

    return v0
.end method

.method public final OooO0O0(I)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO0OO:Llyiahf/vczjk/uy5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/uy5;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    invoke-virtual {v0, p1}, Landroidx/compose/foundation/lazy/layout/OooO0O0;->OooO0OO(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    return-object v0
.end method

.method public final OooO0OO(I)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    invoke-virtual {v0, p1}, Landroidx/compose/foundation/lazy/layout/OooO0O0;->OooO00o(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Ljava/lang/Object;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO0OO:Llyiahf/vczjk/uy5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p1

    return p1
.end method

.method public final OooO0o0(ILjava/lang/Object;Llyiahf/vczjk/zf1;)V
    .locals 7

    const v0, 0x5905c824

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO00o:Llyiahf/vczjk/er4;

    iget-object v3, v0, Llyiahf/vczjk/er4;->OooOOo0:Llyiahf/vczjk/hu4;

    new-instance v0, Llyiahf/vczjk/aq4;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/aq4;-><init>(Llyiahf/vczjk/bq4;I)V

    const v1, 0x2b48c518

    invoke-static {v1, v0, p3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const/16 v6, 0xc00

    move v2, p1

    move-object v1, p2

    move-object v5, p3

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/qqa;->OooO0o0(Ljava/lang/Object;ILlyiahf/vczjk/hu4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    const/4 p1, 0x0

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/bq4;

    if-nez v0, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    check-cast p1, Llyiahf/vczjk/bq4;

    iget-object p1, p1, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bq4;->OooO0O0:Llyiahf/vczjk/zp4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method
