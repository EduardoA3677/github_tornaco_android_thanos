.class public final Llyiahf/vczjk/x37;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animation:Llyiahf/vczjk/jl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jl;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/e47;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jl;Llyiahf/vczjk/e47;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/x37;->$animation:Llyiahf/vczjk/jl;

    iput-object p2, p0, Llyiahf/vczjk/x37;->this$0:Llyiahf/vczjk/e47;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/x37;->OooO0oO()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0oO()V
    .locals 10

    sget-boolean v0, Llyiahf/vczjk/xi;->OooO0Oo:Z

    iget-object v0, p0, Llyiahf/vczjk/x37;->$animation:Llyiahf/vczjk/jl;

    sget-boolean v1, Llyiahf/vczjk/xi;->OooO0Oo:Z

    const/4 v2, 0x0

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/jl;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    new-instance v2, Llyiahf/vczjk/xi;

    iget-object v1, v0, Llyiahf/vczjk/jl;->OooO0O0:Llyiahf/vczjk/wl;

    iget-object v3, v0, Llyiahf/vczjk/jl;->OooO00o:Llyiahf/vczjk/gi;

    iget-object v0, v0, Llyiahf/vczjk/jl;->OooO0OO:Llyiahf/vczjk/zw9;

    invoke-direct {v2, v3, v1, v0}, Llyiahf/vczjk/xi;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/wl;Llyiahf/vczjk/zw9;)V

    :goto_0
    if-eqz v2, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/x37;->this$0:Llyiahf/vczjk/e47;

    iget-object v0, v0, Llyiahf/vczjk/e47;->OooO0OO:Ljava/util/LinkedHashMap;

    new-instance v1, Llyiahf/vczjk/wi;

    invoke-direct {v1}, Llyiahf/vczjk/wi;-><init>()V

    iget-object v3, v2, Llyiahf/vczjk/xi;->OooO0OO:Llyiahf/vczjk/gi;

    invoke-virtual {v3}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v7

    iget-object v3, v2, Llyiahf/vczjk/xi;->OooO0OO:Llyiahf/vczjk/gi;

    invoke-virtual {v3}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v8

    iget-object v3, v2, Llyiahf/vczjk/xi;->OooO00o:Llyiahf/vczjk/zw9;

    iget-object v3, v3, Llyiahf/vczjk/zw9;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    iput-object v3, v1, Llyiahf/vczjk/wi;->OooO0O0:Ljava/lang/Object;

    iget-object v5, v2, Llyiahf/vczjk/xi;->OooO0O0:Llyiahf/vczjk/wl;

    iget-object v3, v2, Llyiahf/vczjk/xi;->OooO0OO:Llyiahf/vczjk/gi;

    iget-object v6, v3, Llyiahf/vczjk/gi;->OooO00o:Llyiahf/vczjk/m1a;

    move-object v4, v6

    check-cast v4, Llyiahf/vczjk/n1a;

    iget-object v9, v4, Llyiahf/vczjk/n1a;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object v3, v3, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v3, v3, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    invoke-interface {v9, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v9, v4

    new-instance v4, Llyiahf/vczjk/fg9;

    iget-object v9, v9, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v9, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v9, v3

    check-cast v9, Llyiahf/vczjk/dm;

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/fg9;-><init>(Llyiahf/vczjk/wl;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/dm;)V

    iput-object v4, v1, Llyiahf/vczjk/wi;->OooO0OO:Ljava/lang/Object;

    invoke-interface {v0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    check-cast v2, Landroidx/compose/animation/tooling/ComposeAnimation;

    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/x37;->this$0:Llyiahf/vczjk/e47;

    iget-object v1, p0, Llyiahf/vczjk/x37;->$animation:Llyiahf/vczjk/jl;

    iget-object v1, v1, Llyiahf/vczjk/jl;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v0}, Llyiahf/vczjk/e47;->OooO00o()V

    return-void
.end method
