.class public final Llyiahf/vczjk/oy9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/n1a;

.field public final OooO0O0:Llyiahf/vczjk/qs5;

.field public final synthetic OooO0OO:Llyiahf/vczjk/bz9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/n1a;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oy9;->OooO0OO:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/oy9;->OooO00o:Llyiahf/vczjk/n1a;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/oy9;->OooO0O0:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ny9;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/oy9;->OooO0O0:Llyiahf/vczjk/qs5;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ny9;

    iget-object v2, p0, Llyiahf/vczjk/oy9;->OooO0OO:Llyiahf/vczjk/bz9;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/ny9;

    new-instance v3, Llyiahf/vczjk/uy9;

    iget-object v4, v2, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v4}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    invoke-interface {p2, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    iget-object v5, v2, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v5}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    move-result-object v5

    invoke-interface {p2, v5}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/oy9;->OooO00o:Llyiahf/vczjk/n1a;

    iget-object v7, v6, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v7, v5}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/dm;

    invoke-virtual {v5}, Llyiahf/vczjk/dm;->OooO0Oo()V

    invoke-direct {v3, v2, v4, v5, v6}, Llyiahf/vczjk/uy9;-><init>(Llyiahf/vczjk/bz9;Ljava/lang/Object;Llyiahf/vczjk/dm;Llyiahf/vczjk/m1a;)V

    invoke-direct {v1, p0, v3, p1, p2}, Llyiahf/vczjk/ny9;-><init>(Llyiahf/vczjk/oy9;Llyiahf/vczjk/uy9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, v2, Llyiahf/vczjk/bz9;->OooO:Llyiahf/vczjk/tw8;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/tw8;->add(Ljava/lang/Object;)Z

    :cond_0
    check-cast p2, Llyiahf/vczjk/rm4;

    iput-object p2, v1, Llyiahf/vczjk/ny9;->OooOOOO:Llyiahf/vczjk/rm4;

    check-cast p1, Llyiahf/vczjk/rm4;

    iput-object p1, v1, Llyiahf/vczjk/ny9;->OooOOO:Llyiahf/vczjk/rm4;

    invoke-virtual {v2}, Llyiahf/vczjk/bz9;->OooO0o()Llyiahf/vczjk/sy9;

    move-result-object p1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ny9;->OooO00o(Llyiahf/vczjk/sy9;)V

    return-object v1
.end method
