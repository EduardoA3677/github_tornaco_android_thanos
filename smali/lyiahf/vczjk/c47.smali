.class public final Llyiahf/vczjk/c47;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animation:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/e47;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/e47;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/c47;->$animation:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/c47;->this$0:Llyiahf/vczjk/e47;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/c47;->OooO0oO()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0oO()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/c47;->$animation:Llyiahf/vczjk/bz9;

    iget-object v1, v0, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v1}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getEnumConstants()[Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    goto :goto_0

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    :goto_0
    new-instance v2, Llyiahf/vczjk/ez9;

    iget-object v3, v0, Llyiahf/vczjk/bz9;->OooO0OO:Ljava/lang/String;

    if-nez v3, :cond_1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/gf4;->OooO0O0()Ljava/lang/String;

    :cond_1
    invoke-direct {v2, v0}, Llyiahf/vczjk/ez9;-><init>(Llyiahf/vczjk/bz9;)V

    goto :goto_1

    :cond_2
    const/4 v2, 0x0

    :goto_1
    if-eqz v2, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/c47;->this$0:Llyiahf/vczjk/e47;

    iget-object v0, v0, Llyiahf/vczjk/e47;->OooO00o:Ljava/util/LinkedHashMap;

    new-instance v1, Llyiahf/vczjk/dz9;

    invoke-direct {v1, v2}, Llyiahf/vczjk/dz9;-><init>(Llyiahf/vczjk/cz9;)V

    invoke-interface {v0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    check-cast v2, Landroidx/compose/animation/tooling/ComposeAnimation;

    return-void

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/c47;->this$0:Llyiahf/vczjk/e47;

    iget-object v1, p0, Llyiahf/vczjk/c47;->$animation:Llyiahf/vczjk/bz9;

    iget-object v1, v1, Llyiahf/vczjk/bz9;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v0}, Llyiahf/vczjk/e47;->OooO00o()V

    return-void
.end method
