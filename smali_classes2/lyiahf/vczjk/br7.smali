.class public final Llyiahf/vczjk/br7;
.super Llyiahf/vczjk/cr7;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/uf5;

.field public final synthetic OooO0O0:I

.field public final synthetic OooO0OO:[B


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uf5;I[B)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/br7;->OooO00o:Llyiahf/vczjk/uf5;

    iput p2, p0, Llyiahf/vczjk/br7;->OooO0O0:I

    iput-object p3, p0, Llyiahf/vczjk/br7;->OooO0OO:[B

    return-void
.end method


# virtual methods
.method public final OooO00o()J
    .locals 2

    iget v0, p0, Llyiahf/vczjk/br7;->OooO0O0:I

    int-to-long v0, v0

    return-wide v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/uf5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/br7;->OooO00o:Llyiahf/vczjk/uf5;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/mj0;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/br7;->OooO0OO:[B

    iget v1, p0, Llyiahf/vczjk/br7;->OooO0O0:I

    invoke-interface {p1, v1, v0}, Llyiahf/vczjk/mj0;->OoooO0O(I[B)Llyiahf/vczjk/mj0;

    return-void
.end method
