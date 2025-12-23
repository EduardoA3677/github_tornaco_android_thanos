.class public final Llyiahf/vczjk/w68;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $backgroundColor:J

.field final synthetic $bottomBar:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $contentColor:J

.field final synthetic $contentWindowInsets:Llyiahf/vczjk/kna;

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

.field final synthetic $drawerGesturesEnabled:Z

.field final synthetic $drawerScrimColor:J

.field final synthetic $drawerShape:Llyiahf/vczjk/qj8;

.field final synthetic $floatingActionButton:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $floatingActionButtonPosition:I

.field final synthetic $isFloatingActionButtonDocked:Z

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $scaffoldState:Llyiahf/vczjk/n78;

.field final synthetic $snackbarHost:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $topBar:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kl5;Llyiahf/vczjk/n78;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;IZLlyiahf/vczjk/bf3;ZLlyiahf/vczjk/qj8;FJJJJJLlyiahf/vczjk/bf3;III)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/w68;->$contentWindowInsets:Llyiahf/vczjk/kna;

    iput-object p2, p0, Llyiahf/vczjk/w68;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/w68;->$scaffoldState:Llyiahf/vczjk/n78;

    iput-object p4, p0, Llyiahf/vczjk/w68;->$topBar:Llyiahf/vczjk/ze3;

    iput-object p5, p0, Llyiahf/vczjk/w68;->$bottomBar:Llyiahf/vczjk/ze3;

    iput-object p6, p0, Llyiahf/vczjk/w68;->$snackbarHost:Llyiahf/vczjk/bf3;

    iput-object p7, p0, Llyiahf/vczjk/w68;->$floatingActionButton:Llyiahf/vczjk/ze3;

    iput p8, p0, Llyiahf/vczjk/w68;->$floatingActionButtonPosition:I

    iput-boolean p9, p0, Llyiahf/vczjk/w68;->$isFloatingActionButtonDocked:Z

    iput-object p10, p0, Llyiahf/vczjk/w68;->$drawerContent:Llyiahf/vczjk/bf3;

    iput-boolean p11, p0, Llyiahf/vczjk/w68;->$drawerGesturesEnabled:Z

    iput-object p12, p0, Llyiahf/vczjk/w68;->$drawerShape:Llyiahf/vczjk/qj8;

    iput p13, p0, Llyiahf/vczjk/w68;->$drawerElevation:F

    iput-wide p14, p0, Llyiahf/vczjk/w68;->$drawerBackgroundColor:J

    move-wide/from16 p1, p16

    iput-wide p1, p0, Llyiahf/vczjk/w68;->$drawerContentColor:J

    move-wide/from16 p1, p18

    iput-wide p1, p0, Llyiahf/vczjk/w68;->$drawerScrimColor:J

    move-wide/from16 p1, p20

    iput-wide p1, p0, Llyiahf/vczjk/w68;->$backgroundColor:J

    move-wide/from16 p1, p22

    iput-wide p1, p0, Llyiahf/vczjk/w68;->$contentColor:J

    move-object/from16 p1, p24

    iput-object p1, p0, Llyiahf/vczjk/w68;->$content:Llyiahf/vczjk/bf3;

    move/from16 p1, p25

    iput p1, p0, Llyiahf/vczjk/w68;->$$changed:I

    move/from16 p1, p26

    iput p1, p0, Llyiahf/vczjk/w68;->$$changed1:I

    move/from16 p1, p27

    iput p1, p0, Llyiahf/vczjk/w68;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    move-object/from16 v0, p0

    move-object/from16 v25, p1

    check-cast v25, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/w68;->$contentWindowInsets:Llyiahf/vczjk/kna;

    iget-object v2, v0, Llyiahf/vczjk/w68;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, v0, Llyiahf/vczjk/w68;->$scaffoldState:Llyiahf/vczjk/n78;

    iget-object v4, v0, Llyiahf/vczjk/w68;->$topBar:Llyiahf/vczjk/ze3;

    iget-object v5, v0, Llyiahf/vczjk/w68;->$bottomBar:Llyiahf/vczjk/ze3;

    iget-object v6, v0, Llyiahf/vczjk/w68;->$snackbarHost:Llyiahf/vczjk/bf3;

    iget-object v7, v0, Llyiahf/vczjk/w68;->$floatingActionButton:Llyiahf/vczjk/ze3;

    iget v8, v0, Llyiahf/vczjk/w68;->$floatingActionButtonPosition:I

    iget-boolean v9, v0, Llyiahf/vczjk/w68;->$isFloatingActionButtonDocked:Z

    iget-object v10, v0, Llyiahf/vczjk/w68;->$drawerContent:Llyiahf/vczjk/bf3;

    iget-boolean v11, v0, Llyiahf/vczjk/w68;->$drawerGesturesEnabled:Z

    iget-object v12, v0, Llyiahf/vczjk/w68;->$drawerShape:Llyiahf/vczjk/qj8;

    iget v13, v0, Llyiahf/vczjk/w68;->$drawerElevation:F

    iget-wide v14, v0, Llyiahf/vczjk/w68;->$drawerBackgroundColor:J

    move-object/from16 v16, v1

    move-object/from16 v17, v2

    iget-wide v1, v0, Llyiahf/vczjk/w68;->$drawerContentColor:J

    move-wide/from16 v18, v1

    iget-wide v1, v0, Llyiahf/vczjk/w68;->$drawerScrimColor:J

    move-wide/from16 v20, v1

    iget-wide v1, v0, Llyiahf/vczjk/w68;->$backgroundColor:J

    move-wide/from16 v22, v1

    iget-wide v1, v0, Llyiahf/vczjk/w68;->$contentColor:J

    move-wide/from16 v26, v1

    iget-object v1, v0, Llyiahf/vczjk/w68;->$content:Llyiahf/vczjk/bf3;

    iget v2, v0, Llyiahf/vczjk/w68;->$$changed:I

    or-int/lit8 v2, v2, 0x1

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v2

    move-object/from16 v24, v1

    iget v1, v0, Llyiahf/vczjk/w68;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/w68;->$$default:I

    move/from16 v28, v1

    move-object/from16 v1, v16

    move-wide/from16 v29, v26

    move/from16 v27, p1

    move/from16 v26, v2

    move-object/from16 v2, v17

    move-wide/from16 v16, v18

    move-wide/from16 v18, v20

    move-wide/from16 v20, v22

    move-wide/from16 v22, v29

    invoke-static/range {v1 .. v28}, Llyiahf/vczjk/k78;->OooO0O0(Llyiahf/vczjk/kna;Llyiahf/vczjk/kl5;Llyiahf/vczjk/n78;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;IZLlyiahf/vczjk/bf3;ZLlyiahf/vczjk/qj8;FJJJJJLlyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
