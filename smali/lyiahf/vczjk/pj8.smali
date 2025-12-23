.class public final Llyiahf/vczjk/pj8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $rootToAttach:Llyiahf/vczjk/nj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nj8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pj8;->$rootToAttach:Llyiahf/vczjk/nj8;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/xn6;

    invoke-virtual {p1}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nj8;

    invoke-virtual {p1}, Llyiahf/vczjk/nj8;->OooO00o()Llyiahf/vczjk/nj8;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/pj8;->$rootToAttach:Llyiahf/vczjk/nj8;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
