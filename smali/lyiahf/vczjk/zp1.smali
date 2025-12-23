.class public final Llyiahf/vczjk/zp1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/lx4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zp1;->$state:Llyiahf/vczjk/lx4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/xn4;

    iget-object v0, p0, Llyiahf/vczjk/zp1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iput-object p1, v0, Llyiahf/vczjk/nm9;->OooO0OO:Llyiahf/vczjk/xn4;

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
