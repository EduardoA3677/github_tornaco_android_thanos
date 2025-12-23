.class public final Llyiahf/vczjk/ph2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $drawerBackgroundColor:J

.field final synthetic $drawerContent:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $drawerContentColor:J

.field final synthetic $drawerElevation:F

.field final synthetic $drawerShape:Llyiahf/vczjk/qj8;

.field final synthetic $drawerState:Llyiahf/vczjk/li2;

.field final synthetic $gesturesEnabled:Z

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $scrimColor:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/li2;ZLlyiahf/vczjk/qj8;FJJJLlyiahf/vczjk/ze3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ph2;->$drawerContent:Llyiahf/vczjk/bf3;

    iput-object p2, p0, Llyiahf/vczjk/ph2;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/ph2;->$drawerState:Llyiahf/vczjk/li2;

    iput-boolean p4, p0, Llyiahf/vczjk/ph2;->$gesturesEnabled:Z

    iput-object p5, p0, Llyiahf/vczjk/ph2;->$drawerShape:Llyiahf/vczjk/qj8;

    iput p6, p0, Llyiahf/vczjk/ph2;->$drawerElevation:F

    iput-wide p7, p0, Llyiahf/vczjk/ph2;->$drawerBackgroundColor:J

    iput-wide p9, p0, Llyiahf/vczjk/ph2;->$drawerContentColor:J

    iput-wide p11, p0, Llyiahf/vczjk/ph2;->$scrimColor:J

    iput-object p13, p0, Llyiahf/vczjk/ph2;->$content:Llyiahf/vczjk/ze3;

    iput p14, p0, Llyiahf/vczjk/ph2;->$$changed:I

    iput p15, p0, Llyiahf/vczjk/ph2;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v14, p1

    check-cast v14, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/ph2;->$drawerContent:Llyiahf/vczjk/bf3;

    iget-object v2, v0, Llyiahf/vczjk/ph2;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, v0, Llyiahf/vczjk/ph2;->$drawerState:Llyiahf/vczjk/li2;

    iget-boolean v4, v0, Llyiahf/vczjk/ph2;->$gesturesEnabled:Z

    iget-object v5, v0, Llyiahf/vczjk/ph2;->$drawerShape:Llyiahf/vczjk/qj8;

    iget v6, v0, Llyiahf/vczjk/ph2;->$drawerElevation:F

    iget-wide v7, v0, Llyiahf/vczjk/ph2;->$drawerBackgroundColor:J

    iget-wide v9, v0, Llyiahf/vczjk/ph2;->$drawerContentColor:J

    iget-wide v11, v0, Llyiahf/vczjk/ph2;->$scrimColor:J

    iget-object v13, v0, Llyiahf/vczjk/ph2;->$content:Llyiahf/vczjk/ze3;

    iget v15, v0, Llyiahf/vczjk/ph2;->$$changed:I

    or-int/lit8 v15, v15, 0x1

    invoke-static {v15}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v15

    move-object/from16 v16, v1

    iget v1, v0, Llyiahf/vczjk/ph2;->$$default:I

    move-object/from16 v17, v16

    move/from16 v16, v1

    move-object/from16 v1, v17

    invoke-static/range {v1 .. v16}, Llyiahf/vczjk/xh2;->OooO00o(Llyiahf/vczjk/bf3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/li2;ZLlyiahf/vczjk/qj8;FJJJLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
