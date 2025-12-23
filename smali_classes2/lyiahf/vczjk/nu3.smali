.class public final synthetic Llyiahf/vczjk/nu3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V
    .locals 0

    iput p7, p0, Llyiahf/vczjk/nu3;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/nu3;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/nu3;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/nu3;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/nu3;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/nu3;->OooOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    move-object/from16 v0, p0

    const/4 v1, 0x7

    const/4 v2, 0x1

    iget-object v3, v0, Llyiahf/vczjk/nu3;->OooOOOo:Ljava/lang/Object;

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v5, v0, Llyiahf/vczjk/nu3;->OooOOOO:Ljava/lang/Object;

    iget-object v6, v0, Llyiahf/vczjk/nu3;->OooOOo:Ljava/lang/Object;

    iget-object v7, v0, Llyiahf/vczjk/nu3;->OooOOo0:Ljava/lang/Object;

    iget-object v8, v0, Llyiahf/vczjk/nu3;->OooOOO:Ljava/lang/Object;

    iget v9, v0, Llyiahf/vczjk/nu3;->OooOOO0:I

    packed-switch v9, :pswitch_data_0

    move-object/from16 v15, p1

    check-cast v15, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v16

    move-object v10, v8

    check-cast v10, Llyiahf/vczjk/a91;

    move-object v13, v7

    check-cast v13, Llyiahf/vczjk/le3;

    move-object v14, v6

    check-cast v14, Llyiahf/vczjk/jx9;

    move-object v11, v5

    check-cast v11, Llyiahf/vczjk/bf3;

    move-object v12, v3

    check-cast v12, Llyiahf/vczjk/a91;

    invoke-static/range {v10 .. v16}, Llyiahf/vczjk/xr6;->OooO0o0(Llyiahf/vczjk/a91;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/jx9;Llyiahf/vczjk/rf1;I)V

    return-object v4

    :pswitch_0
    move-object/from16 v22, p1

    check-cast v22, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v23

    move-object/from16 v20, v7

    check-cast v20, Llyiahf/vczjk/i48;

    move-object/from16 v21, v6

    check-cast v21, Ljava/lang/String;

    move-object/from16 v17, v8

    check-cast v17, Llyiahf/vczjk/j28;

    move-object/from16 v18, v5

    check-cast v18, Llyiahf/vczjk/cm4;

    move-object/from16 v19, v3

    check-cast v19, Ljava/util/List;

    invoke-static/range {v17 .. v23}, Llyiahf/vczjk/kh6;->OooO00o(Llyiahf/vczjk/j28;Llyiahf/vczjk/cm4;Ljava/util/List;Llyiahf/vczjk/i48;Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    return-object v4

    :pswitch_1
    move-object/from16 v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    check-cast v5, Lnow/fortuitous/thanos/process/v2/RunningService;

    check-cast v3, Llyiahf/vczjk/oy7;

    check-cast v7, Llyiahf/vczjk/le3;

    move-object v9, v6

    check-cast v9, Llyiahf/vczjk/le3;

    check-cast v8, Llyiahf/vczjk/qs5;

    move-object v6, v5

    move-object v5, v8

    move-object v8, v7

    move-object v7, v3

    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/mt6;->OooO0o(Llyiahf/vczjk/qs5;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/oy7;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v4

    :pswitch_2
    move-object/from16 v17, p1

    check-cast v17, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v18

    move-object v15, v7

    check-cast v15, Llyiahf/vczjk/oe3;

    move-object/from16 v16, v6

    check-cast v16, Llyiahf/vczjk/oe3;

    move-object v12, v8

    check-cast v12, Llyiahf/vczjk/bi6;

    move-object v13, v5

    check-cast v13, Llyiahf/vczjk/gc6;

    move-object v14, v3

    check-cast v14, Llyiahf/vczjk/oe3;

    invoke-static/range {v12 .. v18}, Llyiahf/vczjk/mc4;->OooOO0O(Llyiahf/vczjk/bi6;Llyiahf/vczjk/gc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v4

    :pswitch_3
    move-object/from16 v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    check-cast v8, Llyiahf/vczjk/di6;

    check-cast v7, Llyiahf/vczjk/oe3;

    move-object v9, v6

    check-cast v9, Llyiahf/vczjk/oe3;

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/ow5;

    check-cast v3, Llyiahf/vczjk/le3;

    move-object v5, v8

    move-object v8, v7

    move-object v7, v3

    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/yi4;->OooOOOO(Llyiahf/vczjk/di6;Llyiahf/vczjk/ow5;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v4

    :pswitch_4
    move-object/from16 v17, p1

    check-cast v17, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v1, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OoooO0O:I

    const v1, 0x8001

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v18

    move-object v15, v7

    check-cast v15, Llyiahf/vczjk/le3;

    move-object/from16 v16, v6

    check-cast v16, Llyiahf/vczjk/le3;

    move-object v12, v8

    check-cast v12, Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    move-object v13, v5

    check-cast v13, Llyiahf/vczjk/le3;

    move-object v14, v3

    check-cast v14, Llyiahf/vczjk/le3;

    invoke-virtual/range {v12 .. v18}, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OooOooO(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v4

    :pswitch_5
    move-object/from16 v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    move-object v9, v6

    check-cast v9, Llyiahf/vczjk/kd;

    check-cast v8, Llyiahf/vczjk/iv3;

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/kl5;

    move-object v1, v7

    iget-object v7, v0, Llyiahf/vczjk/nu3;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/hv3;

    move-object v5, v8

    move-object v8, v1

    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/l4a;->OooO0o0(Llyiahf/vczjk/iv3;Llyiahf/vczjk/kl5;Ljava/lang/Object;Llyiahf/vczjk/hv3;Llyiahf/vczjk/kd;Llyiahf/vczjk/rf1;I)V

    return-object v4

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
