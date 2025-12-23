.class public final Llyiahf/vczjk/h1a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xj2;


# instance fields
.field public final OooO00o:I

.field public final OooO0O0:I

.field public final OooO0OO:Llyiahf/vczjk/ik2;


# direct methods
.method public constructor <init>(IILlyiahf/vczjk/ik2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/h1a;->OooO00o:I

    iput p2, p0, Llyiahf/vczjk/h1a;->OooO0O0:I

    iput-object p3, p0, Llyiahf/vczjk/h1a;->OooO0OO:Llyiahf/vczjk/ik2;

    return-void
.end method

.method public constructor <init>(ILlyiahf/vczjk/ik2;I)V
    .locals 0

    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_0

    sget-object p2, Llyiahf/vczjk/jk2;->OooO00o:Llyiahf/vczjk/cu1;

    :cond_0
    const/4 p3, 0x0

    invoke-direct {p0, p1, p3, p2}, Llyiahf/vczjk/h1a;-><init>(IILlyiahf/vczjk/ik2;)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/aea;
    .locals 3

    new-instance p1, Llyiahf/vczjk/or3;

    iget v0, p0, Llyiahf/vczjk/h1a;->OooO00o:I

    iget v1, p0, Llyiahf/vczjk/h1a;->OooO0O0:I

    iget-object v2, p0, Llyiahf/vczjk/h1a;->OooO0OO:Llyiahf/vczjk/ik2;

    invoke-direct {p1, v0, v1, v2}, Llyiahf/vczjk/or3;-><init>(IILlyiahf/vczjk/ik2;)V

    return-object p1
.end method

.method public final OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;
    .locals 3

    new-instance p1, Llyiahf/vczjk/or3;

    iget v0, p0, Llyiahf/vczjk/h1a;->OooO00o:I

    iget v1, p0, Llyiahf/vczjk/h1a;->OooO0O0:I

    iget-object v2, p0, Llyiahf/vczjk/h1a;->OooO0OO:Llyiahf/vczjk/ik2;

    invoke-direct {p1, v0, v1, v2}, Llyiahf/vczjk/or3;-><init>(IILlyiahf/vczjk/ik2;)V

    return-object p1
.end method

.method public final OooO0o()Llyiahf/vczjk/bea;
    .locals 4

    sget-object v0, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance v0, Llyiahf/vczjk/or3;

    iget v1, p0, Llyiahf/vczjk/h1a;->OooO00o:I

    iget v2, p0, Llyiahf/vczjk/h1a;->OooO0O0:I

    iget-object v3, p0, Llyiahf/vczjk/h1a;->OooO0OO:Llyiahf/vczjk/ik2;

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/or3;-><init>(IILlyiahf/vczjk/ik2;)V

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    instance-of v0, p1, Llyiahf/vczjk/h1a;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/h1a;

    iget v0, p1, Llyiahf/vczjk/h1a;->OooO00o:I

    iget v2, p0, Llyiahf/vczjk/h1a;->OooO00o:I

    if-ne v0, v2, :cond_0

    iget v0, p1, Llyiahf/vczjk/h1a;->OooO0O0:I

    iget v2, p0, Llyiahf/vczjk/h1a;->OooO0O0:I

    if-ne v0, v2, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/h1a;->OooO0OO:Llyiahf/vczjk/ik2;

    iget-object v0, p0, Llyiahf/vczjk/h1a;->OooO0OO:Llyiahf/vczjk/ik2;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    return v1
.end method

.method public final hashCode()I
    .locals 2

    iget v0, p0, Llyiahf/vczjk/h1a;->OooO00o:I

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Llyiahf/vczjk/h1a;->OooO0OO:Llyiahf/vczjk/ik2;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    iget v0, p0, Llyiahf/vczjk/h1a;->OooO0O0:I

    add-int/2addr v1, v0

    return v1
.end method
