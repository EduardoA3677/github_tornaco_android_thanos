.class public final Llyiahf/vczjk/a78;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
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
.method public constructor <init>(ZILlyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zs5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/n78;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/a78;->$isFloatingActionButtonDocked:Z

    iput p2, p0, Llyiahf/vczjk/a78;->$floatingActionButtonPosition:I

    iput-object p3, p0, Llyiahf/vczjk/a78;->$topBar:Llyiahf/vczjk/ze3;

    iput-object p4, p0, Llyiahf/vczjk/a78;->$content:Llyiahf/vczjk/bf3;

    iput-object p5, p0, Llyiahf/vczjk/a78;->$floatingActionButton:Llyiahf/vczjk/ze3;

    iput-object p6, p0, Llyiahf/vczjk/a78;->$safeInsets:Llyiahf/vczjk/zs5;

    iput-object p7, p0, Llyiahf/vczjk/a78;->$bottomBar:Llyiahf/vczjk/ze3;

    iput-object p8, p0, Llyiahf/vczjk/a78;->$snackbarHost:Llyiahf/vczjk/bf3;

    iput-object p9, p0, Llyiahf/vczjk/a78;->$scaffoldState:Llyiahf/vczjk/n78;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/zf1;

    invoke-virtual {v9, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-boolean v1, p0, Llyiahf/vczjk/a78;->$isFloatingActionButtonDocked:Z

    iget v2, p0, Llyiahf/vczjk/a78;->$floatingActionButtonPosition:I

    iget-object v3, p0, Llyiahf/vczjk/a78;->$topBar:Llyiahf/vczjk/ze3;

    iget-object v4, p0, Llyiahf/vczjk/a78;->$content:Llyiahf/vczjk/bf3;

    new-instance p1, Llyiahf/vczjk/z68;

    iget-object p2, p0, Llyiahf/vczjk/a78;->$snackbarHost:Llyiahf/vczjk/bf3;

    iget-object v0, p0, Llyiahf/vczjk/a78;->$scaffoldState:Llyiahf/vczjk/n78;

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/z68;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/n78;)V

    const p2, 0x19dce333

    invoke-static {p2, p1, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/a78;->$floatingActionButton:Llyiahf/vczjk/ze3;

    iget-object v7, p0, Llyiahf/vczjk/a78;->$safeInsets:Llyiahf/vczjk/zs5;

    iget-object v8, p0, Llyiahf/vczjk/a78;->$bottomBar:Llyiahf/vczjk/ze3;

    const/16 v10, 0x6000

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/k78;->OooO0OO(ZILlyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/kna;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
