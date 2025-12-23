.class public final Llyiahf/vczjk/zi9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $editable:Z

.field final synthetic $imeAction:I

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $onValueChange:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $singleLine:Z

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $undoManager:Llyiahf/vczjk/l8a;

.field final synthetic $value:Llyiahf/vczjk/gl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;ZZLlyiahf/vczjk/s86;Llyiahf/vczjk/l8a;Llyiahf/vczjk/kx4;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zi9;->$state:Llyiahf/vczjk/lx4;

    iput-object p2, p0, Llyiahf/vczjk/zi9;->$manager:Llyiahf/vczjk/mk9;

    iput-object p3, p0, Llyiahf/vczjk/zi9;->$value:Llyiahf/vczjk/gl9;

    iput-boolean p4, p0, Llyiahf/vczjk/zi9;->$editable:Z

    iput-boolean p5, p0, Llyiahf/vczjk/zi9;->$singleLine:Z

    iput-object p6, p0, Llyiahf/vczjk/zi9;->$offsetMapping:Llyiahf/vczjk/s86;

    iput-object p7, p0, Llyiahf/vczjk/zi9;->$undoManager:Llyiahf/vczjk/l8a;

    iput-object p8, p0, Llyiahf/vczjk/zi9;->$onValueChange:Llyiahf/vczjk/oe3;

    iput p9, p0, Llyiahf/vczjk/zi9;->$imeAction:I

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/kl5;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x32c59664

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v3, :cond_0

    new-instance v2, Llyiahf/vczjk/fn9;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    move-object v10, v2

    check-cast v10, Llyiahf/vczjk/fn9;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v3, :cond_1

    new-instance v2, Llyiahf/vczjk/p02;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v13, v2

    check-cast v13, Llyiahf/vczjk/p02;

    new-instance v16, Llyiahf/vczjk/yi9;

    iget-object v5, v0, Llyiahf/vczjk/zi9;->$state:Llyiahf/vczjk/lx4;

    iget-object v6, v0, Llyiahf/vczjk/zi9;->$manager:Llyiahf/vczjk/mk9;

    iget-object v7, v0, Llyiahf/vczjk/zi9;->$value:Llyiahf/vczjk/gl9;

    iget-boolean v8, v0, Llyiahf/vczjk/zi9;->$editable:Z

    iget-boolean v9, v0, Llyiahf/vczjk/zi9;->$singleLine:Z

    iget-object v11, v0, Llyiahf/vczjk/zi9;->$offsetMapping:Llyiahf/vczjk/s86;

    iget-object v12, v0, Llyiahf/vczjk/zi9;->$undoManager:Llyiahf/vczjk/l8a;

    iget-object v14, v0, Llyiahf/vczjk/zi9;->$onValueChange:Llyiahf/vczjk/oe3;

    iget v15, v0, Llyiahf/vczjk/zi9;->$imeAction:I

    move-object/from16 v4, v16

    invoke-direct/range {v4 .. v15}, Llyiahf/vczjk/yi9;-><init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;ZZLlyiahf/vczjk/fn9;Llyiahf/vczjk/s86;Llyiahf/vczjk/l8a;Llyiahf/vczjk/p02;Llyiahf/vczjk/oe3;I)V

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_2

    if-ne v6, v3, :cond_3

    :cond_2
    new-instance v14, Llyiahf/vczjk/o00000;

    const-string v19, "process-ZmokQxo(Landroid/view/KeyEvent;)Z"

    const/16 v20, 0x0

    const/4 v15, 0x1

    const-class v17, Llyiahf/vczjk/yi9;

    const-string v18, "process"

    const/16 v21, 0xe

    move-object/from16 v16, v4

    invoke-direct/range {v14 .. v21}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v6, v14

    :cond_3
    check-cast v6, Llyiahf/vczjk/zf4;

    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-static {v2, v6}, Landroidx/compose/ui/input/key/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v2
.end method
