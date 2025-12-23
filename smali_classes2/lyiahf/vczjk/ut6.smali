.class public final Llyiahf/vczjk/ut6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/ut6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ut6;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ut6;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/ut6;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/ut6;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 14

    move-object v1, p1

    move-object/from16 v6, p2

    sget-object v7, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v0, p0, Llyiahf/vczjk/ut6;->OooOOo0:Ljava/lang/Object;

    const/4 v2, 0x0

    iget-object v3, p0, Llyiahf/vczjk/ut6;->OooOOOo:Ljava/lang/Object;

    iget-object v4, p0, Llyiahf/vczjk/ut6;->OooOOOO:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/ut6;->OooOOO:Ljava/lang/Object;

    iget v8, p0, Llyiahf/vczjk/ut6;->OooOOO0:I

    packed-switch v8, :pswitch_data_0

    new-instance v8, Llyiahf/vczjk/mj9;

    check-cast v5, Llyiahf/vczjk/xr1;

    check-cast v4, Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/rr5;

    invoke-direct {v8, v5, v4, v3, v2}, Llyiahf/vczjk/mj9;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;Llyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V

    new-instance v3, Llyiahf/vczjk/nj9;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-direct {v3, v0}, Llyiahf/vczjk/nj9;-><init>(Llyiahf/vczjk/qs5;)V

    sget-object v0, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    new-instance v4, Llyiahf/vczjk/o37;

    invoke-direct {v4, p1}, Llyiahf/vczjk/o37;-><init>(Llyiahf/vczjk/f62;)V

    new-instance v0, Llyiahf/vczjk/mf9;

    const/4 v5, 0x0

    move-object v2, v8

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/mf9;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v6}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    move-object v0, v7

    :goto_0
    if-ne v0, v1, :cond_1

    move-object v7, v0

    :cond_1
    return-object v7

    :pswitch_0
    new-instance v8, Llyiahf/vczjk/m60;

    move-object v9, v5

    check-cast v9, Llyiahf/vczjk/gl7;

    move-object v11, v3

    check-cast v11, Ljava/util/ArrayList;

    move-object v12, v0

    check-cast v12, Llyiahf/vczjk/oe3;

    move-object v10, v4

    check-cast v10, Llyiahf/vczjk/le3;

    const/16 v13, 0x8

    invoke-direct/range {v8 .. v13}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const/4 v0, 0x7

    invoke-static {p1, v2, v8, v6, v0}, Llyiahf/vczjk/dg9;->OooO0Oo(Llyiahf/vczjk/oy6;Llyiahf/vczjk/zr8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v0, v1, :cond_2

    move-object v7, v0

    :cond_2
    return-object v7

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
