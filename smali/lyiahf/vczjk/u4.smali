.class public final Llyiahf/vczjk/u4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/v4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u4;->this$0:Llyiahf/vczjk/v4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/w4;

    invoke-interface {p1}, Llyiahf/vczjk/w4;->Oooo0o0()Z

    move-result v0

    if-nez v0, :cond_0

    goto/16 :goto_3

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v0

    iget-boolean v0, v0, Llyiahf/vczjk/v4;->OooO0O0:Z

    if-eqz v0, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/w4;->Oooo0O0()V

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/v4;->OooO:Ljava/util/HashMap;

    iget-object v1, p0, Llyiahf/vczjk/u4;->this$0:Llyiahf/vczjk/v4;

    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map$Entry;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/p4;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    invoke-interface {p1}, Llyiahf/vczjk/w4;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v4

    invoke-static {v1, v3, v2, v4}, Llyiahf/vczjk/v4;->OooO00o(Llyiahf/vczjk/v4;Llyiahf/vczjk/p4;ILlyiahf/vczjk/v16;)V

    goto :goto_0

    :cond_2
    invoke-interface {p1}, Llyiahf/vczjk/w4;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/u4;->this$0:Llyiahf/vczjk/v4;

    iget-object v0, v0, Llyiahf/vczjk/v4;->OooO00o:Llyiahf/vczjk/ow6;

    invoke-interface {v0}, Llyiahf/vczjk/w4;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/u4;->this$0:Llyiahf/vczjk/v4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/v4;->OooO0OO(Llyiahf/vczjk/v16;)Ljava/util/Map;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    iget-object v1, p0, Llyiahf/vczjk/u4;->this$0:Llyiahf/vczjk/v4;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/p4;

    invoke-virtual {v1, p1, v2}, Llyiahf/vczjk/v4;->OooO0Oo(Llyiahf/vczjk/v16;Llyiahf/vczjk/p4;)I

    move-result v3

    invoke-static {v1, v2, v3, p1}, Llyiahf/vczjk/v4;->OooO00o(Llyiahf/vczjk/v4;Llyiahf/vczjk/p4;ILlyiahf/vczjk/v16;)V

    goto :goto_2

    :cond_3
    iget-object p1, p1, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_1

    :cond_4
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
