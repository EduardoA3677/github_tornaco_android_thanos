.class public final Llyiahf/vczjk/b78;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
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

.field final synthetic $floatingActionButton:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $floatingActionButtonPosition:I

.field final synthetic $isFloatingActionButtonDocked:Z

.field final synthetic $safeInsets:Llyiahf/vczjk/zs5;

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
.method public constructor <init>(Llyiahf/vczjk/zs5;Llyiahf/vczjk/kna;JJZILlyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/n78;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b78;->$safeInsets:Llyiahf/vczjk/zs5;

    iput-object p2, p0, Llyiahf/vczjk/b78;->$contentWindowInsets:Llyiahf/vczjk/kna;

    iput-wide p3, p0, Llyiahf/vczjk/b78;->$backgroundColor:J

    iput-wide p5, p0, Llyiahf/vczjk/b78;->$contentColor:J

    iput-boolean p7, p0, Llyiahf/vczjk/b78;->$isFloatingActionButtonDocked:Z

    iput p8, p0, Llyiahf/vczjk/b78;->$floatingActionButtonPosition:I

    iput-object p9, p0, Llyiahf/vczjk/b78;->$topBar:Llyiahf/vczjk/ze3;

    iput-object p10, p0, Llyiahf/vczjk/b78;->$content:Llyiahf/vczjk/bf3;

    iput-object p11, p0, Llyiahf/vczjk/b78;->$floatingActionButton:Llyiahf/vczjk/ze3;

    iput-object p12, p0, Llyiahf/vczjk/b78;->$bottomBar:Llyiahf/vczjk/ze3;

    iput-object p13, p0, Llyiahf/vczjk/b78;->$snackbarHost:Llyiahf/vczjk/bf3;

    iput-object p14, p0, Llyiahf/vczjk/b78;->$scaffoldState:Llyiahf/vczjk/n78;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/kl5;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x6

    if-nez v4, :cond_1

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int/2addr v3, v4

    :cond_1
    and-int/lit8 v4, v3, 0x13

    const/16 v5, 0x12

    const/4 v6, 0x1

    if-eq v4, v5, :cond_2

    move v4, v6

    goto :goto_1

    :cond_2
    const/4 v4, 0x0

    :goto_1
    and-int/2addr v3, v6

    move-object v14, v2

    check-cast v14, Llyiahf/vczjk/zf1;

    invoke-virtual {v14, v3, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_5

    iget-object v2, v0, Llyiahf/vczjk/b78;->$safeInsets:Llyiahf/vczjk/zs5;

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    iget-object v3, v0, Llyiahf/vczjk/b78;->$contentWindowInsets:Llyiahf/vczjk/kna;

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    iget-object v3, v0, Llyiahf/vczjk/b78;->$safeInsets:Llyiahf/vczjk/zs5;

    iget-object v4, v0, Llyiahf/vczjk/b78;->$contentWindowInsets:Llyiahf/vczjk/kna;

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_3

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v2, :cond_4

    :cond_3
    new-instance v5, Llyiahf/vczjk/y68;

    invoke-direct {v5, v3, v4}, Llyiahf/vczjk/y68;-><init>(Llyiahf/vczjk/zs5;Llyiahf/vczjk/kna;)V

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v5, Llyiahf/vczjk/oe3;

    sget-object v2, Llyiahf/vczjk/uoa;->OooO00o:Llyiahf/vczjk/ie7;

    new-instance v2, Llyiahf/vczjk/soa;

    invoke-direct {v2, v5}, Llyiahf/vczjk/soa;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    iget-wide v7, v0, Llyiahf/vczjk/b78;->$backgroundColor:J

    iget-wide v9, v0, Llyiahf/vczjk/b78;->$contentColor:J

    new-instance v15, Llyiahf/vczjk/a78;

    iget-boolean v1, v0, Llyiahf/vczjk/b78;->$isFloatingActionButtonDocked:Z

    iget v2, v0, Llyiahf/vczjk/b78;->$floatingActionButtonPosition:I

    iget-object v3, v0, Llyiahf/vczjk/b78;->$topBar:Llyiahf/vczjk/ze3;

    iget-object v4, v0, Llyiahf/vczjk/b78;->$content:Llyiahf/vczjk/bf3;

    iget-object v6, v0, Llyiahf/vczjk/b78;->$floatingActionButton:Llyiahf/vczjk/ze3;

    iget-object v11, v0, Llyiahf/vczjk/b78;->$safeInsets:Llyiahf/vczjk/zs5;

    iget-object v12, v0, Llyiahf/vczjk/b78;->$bottomBar:Llyiahf/vczjk/ze3;

    iget-object v13, v0, Llyiahf/vczjk/b78;->$snackbarHost:Llyiahf/vczjk/bf3;

    move/from16 v16, v1

    iget-object v1, v0, Llyiahf/vczjk/b78;->$scaffoldState:Llyiahf/vczjk/n78;

    move-object/from16 v24, v1

    move/from16 v17, v2

    move-object/from16 v18, v3

    move-object/from16 v19, v4

    move-object/from16 v20, v6

    move-object/from16 v21, v11

    move-object/from16 v22, v12

    move-object/from16 v23, v13

    invoke-direct/range {v15 .. v24}, Llyiahf/vczjk/a78;-><init>(ZILlyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zs5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/n78;)V

    const v1, 0x69ad25e4

    invoke-static {v1, v15, v14}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v13

    const/high16 v15, 0x180000

    const/16 v16, 0x32

    const/4 v6, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    invoke-static/range {v5 .. v16}, Llyiahf/vczjk/rd3;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    goto :goto_2

    :cond_5
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
