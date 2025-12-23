.class public final Llyiahf/vczjk/b47;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animation:Llyiahf/vczjk/ll;

.field final synthetic this$0:Llyiahf/vczjk/e47;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ll;Llyiahf/vczjk/e47;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b47;->$animation:Llyiahf/vczjk/ll;

    iput-object p2, p0, Llyiahf/vczjk/b47;->this$0:Llyiahf/vczjk/e47;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/b47;->OooO0oO()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0oO()V
    .locals 5

    sget-boolean v0, Llyiahf/vczjk/ly3;->OooO0O0:Z

    iget-object v0, p0, Llyiahf/vczjk/b47;->$animation:Llyiahf/vczjk/ll;

    sget-boolean v1, Llyiahf/vczjk/ly3;->OooO0O0:Z

    if-nez v1, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/ly3;

    iget-object v2, v0, Llyiahf/vczjk/ll;->OooO0O0:Llyiahf/vczjk/zw9;

    iget-object v0, v0, Llyiahf/vczjk/ll;->OooO00o:Llyiahf/vczjk/jy3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/ly3;-><init>(Llyiahf/vczjk/jy3;)V

    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/b47;->this$0:Llyiahf/vczjk/e47;

    iget-object v2, v1, Llyiahf/vczjk/e47;->OooO0Oo:Ljava/util/LinkedHashMap;

    new-instance v3, Llyiahf/vczjk/ky3;

    new-instance v4, Llyiahf/vczjk/a47;

    invoke-direct {v4, v1}, Llyiahf/vczjk/a47;-><init>(Llyiahf/vczjk/e47;)V

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/ky3;-><init>(Llyiahf/vczjk/ly3;Llyiahf/vczjk/a47;)V

    invoke-interface {v2, v0, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    check-cast v0, Landroidx/compose/animation/tooling/ComposeAnimation;

    :cond_1
    return-void
.end method
