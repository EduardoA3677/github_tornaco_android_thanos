.class public final synthetic Llyiahf/vczjk/z71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;

.field public final synthetic OooOOoo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/z71;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z71;->OooOOo0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/z71;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/z71;->OooOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/z71;->OooOOoo:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/z71;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p6, p0, Llyiahf/vczjk/z71;->OooOOOo:Llyiahf/vczjk/qs5;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/qs5;Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/t81;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/r71;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/z71;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z71;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/z71;->OooOOo0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/z71;->OooOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/z71;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p5, p0, Llyiahf/vczjk/z71;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p6, p0, Llyiahf/vczjk/z71;->OooOOoo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    iget v0, p0, Llyiahf/vczjk/z71;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/fv4;

    packed-switch v0, :pswitch_data_0

    const-string v0, "$this$LazyColumn"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/ic1;

    iget-object v1, p0, Llyiahf/vczjk/z71;->OooOOO:Llyiahf/vczjk/qs5;

    iget-object v2, p0, Llyiahf/vczjk/z71;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/ic1;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v2, -0x6bdc4233

    const/4 v3, 0x1

    invoke-direct {v1, v2, v0, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p1, v1}, Llyiahf/vczjk/fv4;->OooO0oO(Llyiahf/vczjk/fv4;Llyiahf/vczjk/a91;)V

    new-instance v4, Llyiahf/vczjk/a6;

    iget-object v7, p0, Llyiahf/vczjk/z71;->OooOOOO:Llyiahf/vczjk/qs5;

    iget-object v8, p0, Llyiahf/vczjk/z71;->OooOOOo:Llyiahf/vczjk/qs5;

    iget-object v0, p0, Llyiahf/vczjk/z71;->OooOOo:Ljava/lang/Object;

    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/le3;

    iget-object v0, p0, Llyiahf/vczjk/z71;->OooOOoo:Ljava/lang/Object;

    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/le3;

    const/4 v9, 0x6

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/a6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    new-instance v0, Llyiahf/vczjk/a91;

    const v1, 0x34d6e544

    invoke-direct {v0, v1, v4, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p1, v0}, Llyiahf/vczjk/fv4;->OooO0oO(Llyiahf/vczjk/fv4;Llyiahf/vczjk/a91;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const-string v0, "$this$LazyColumn"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/z71;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/r7a;

    instance-of v2, v1, Llyiahf/vczjk/o7a;

    const/4 v3, 0x1

    if-eqz v2, :cond_0

    new-instance v1, Llyiahf/vczjk/p5;

    const/4 v2, 0x2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/p5;-><init>(Llyiahf/vczjk/qs5;I)V

    new-instance v0, Llyiahf/vczjk/a91;

    const v2, -0x6ad3e942

    invoke-direct {v0, v2, v1, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p1, v0}, Llyiahf/vczjk/fv4;->OooO0oO(Llyiahf/vczjk/fv4;Llyiahf/vczjk/a91;)V

    goto/16 :goto_2

    :cond_0
    instance-of v2, v1, Llyiahf/vczjk/p7a;

    if-eqz v2, :cond_3

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/r7a;

    const-string v1, "null cannot be cast to non-null type github.tornaco.android.thanos.module.compose.common.infra.UiState.Loaded<kotlin.collections.List<github.tornaco.thanos.module.component.manager.redesign.ComponentGroup>>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/p7a;

    iget-object v0, v0, Llyiahf/vczjk/p7a;->OooO00o:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v5, v1

    check-cast v5, Llyiahf/vczjk/b71;

    iget-object v1, v5, Llyiahf/vczjk/b71;->OooO0O0:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    const/16 v2, 0x64

    if-le v1, v2, :cond_1

    move v7, v3

    goto :goto_1

    :cond_1
    const/4 v1, 0x0

    move v7, v1

    :goto_1
    new-instance v4, Llyiahf/vczjk/a81;

    iget-object v1, p0, Llyiahf/vczjk/z71;->OooOOo:Ljava/lang/Object;

    move-object v8, v1

    check-cast v8, Llyiahf/vczjk/t81;

    iget-object v1, p0, Llyiahf/vczjk/z71;->OooOOo0:Ljava/lang/Object;

    move-object v10, v1

    check-cast v10, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    iget-object v6, p0, Llyiahf/vczjk/z71;->OooOOOO:Llyiahf/vczjk/qs5;

    iget-object v13, p0, Llyiahf/vczjk/z71;->OooOOOo:Llyiahf/vczjk/qs5;

    move-object v9, v6

    move-object v6, v5

    move-object v5, v10

    move-object v10, v13

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/a81;-><init>(Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/b71;ZLlyiahf/vczjk/t81;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;)V

    move-object v10, v5

    move-object v5, v6

    move-object v6, v9

    new-instance v1, Llyiahf/vczjk/a91;

    const v2, -0x63f17cbe

    invoke-direct {v1, v2, v4, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p1, v1}, Llyiahf/vczjk/fv4;->OooOO0(Llyiahf/vczjk/fv4;Llyiahf/vczjk/a91;)V

    iget-object v1, p0, Llyiahf/vczjk/z71;->OooOOoo:Ljava/lang/Object;

    move-object v11, v1

    check-cast v11, Llyiahf/vczjk/r71;

    if-nez v7, :cond_2

    new-instance v4, Llyiahf/vczjk/h81;

    move-object v1, v11

    const/4 v11, 0x0

    move-object v9, v8

    move-object v8, v10

    move-object v7, v13

    move-object v10, v1

    invoke-direct/range {v4 .. v11}, Llyiahf/vczjk/h81;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v2, 0x4bd1c211    # 2.749341E7f

    invoke-direct {v1, v2, v4, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p1, v1}, Llyiahf/vczjk/fv4;->OooO0oO(Llyiahf/vczjk/fv4;Llyiahf/vczjk/a91;)V

    goto :goto_0

    :cond_2
    move-object v1, v11

    new-instance v2, Llyiahf/vczjk/v1;

    const/16 v4, 0x12

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    iget-object v9, v5, Llyiahf/vczjk/b71;->OooO0O0:Ljava/util/List;

    invoke-interface {v9}, Ljava/util/List;->size()I

    move-result v4

    new-instance v5, Llyiahf/vczjk/i81;

    invoke-direct {v5, v2, v9}, Llyiahf/vczjk/i81;-><init>(Llyiahf/vczjk/v1;Ljava/util/List;)V

    new-instance v2, Llyiahf/vczjk/j81;

    invoke-direct {v2, v9}, Llyiahf/vczjk/j81;-><init>(Ljava/util/List;)V

    move-object v12, v8

    new-instance v8, Llyiahf/vczjk/k81;

    move-object v11, v1

    invoke-direct/range {v8 .. v13}, Llyiahf/vczjk/k81;-><init>(Ljava/util/List;Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/r71;Llyiahf/vczjk/t81;Llyiahf/vczjk/qs5;)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v6, -0x410876af

    invoke-direct {v1, v6, v8, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {p1, v4, v5, v2, v1}, Llyiahf/vczjk/fv4;->OooO0oo(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    goto/16 :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_5

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_5
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
