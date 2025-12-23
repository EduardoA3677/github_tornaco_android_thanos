.class public final Llyiahf/vczjk/g78;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

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

.field final synthetic $contentWindowInsets:Llyiahf/vczjk/kna;

.field final synthetic $fab:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $fabPosition:I

.field final synthetic $isFabDocked:Z

.field final synthetic $snackbar:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
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
.method public constructor <init>(ZILlyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/kna;Llyiahf/vczjk/ze3;I)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/g78;->$isFabDocked:Z

    iput p2, p0, Llyiahf/vczjk/g78;->$fabPosition:I

    iput-object p3, p0, Llyiahf/vczjk/g78;->$topBar:Llyiahf/vczjk/ze3;

    iput-object p4, p0, Llyiahf/vczjk/g78;->$content:Llyiahf/vczjk/bf3;

    iput-object p5, p0, Llyiahf/vczjk/g78;->$snackbar:Llyiahf/vczjk/ze3;

    iput-object p6, p0, Llyiahf/vczjk/g78;->$fab:Llyiahf/vczjk/ze3;

    iput-object p7, p0, Llyiahf/vczjk/g78;->$contentWindowInsets:Llyiahf/vczjk/kna;

    iput-object p8, p0, Llyiahf/vczjk/g78;->$bottomBar:Llyiahf/vczjk/ze3;

    iput p9, p0, Llyiahf/vczjk/g78;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-boolean v0, p0, Llyiahf/vczjk/g78;->$isFabDocked:Z

    iget v1, p0, Llyiahf/vczjk/g78;->$fabPosition:I

    iget-object v2, p0, Llyiahf/vczjk/g78;->$topBar:Llyiahf/vczjk/ze3;

    iget-object v3, p0, Llyiahf/vczjk/g78;->$content:Llyiahf/vczjk/bf3;

    iget-object v4, p0, Llyiahf/vczjk/g78;->$snackbar:Llyiahf/vczjk/ze3;

    iget-object v5, p0, Llyiahf/vczjk/g78;->$fab:Llyiahf/vczjk/ze3;

    iget-object v6, p0, Llyiahf/vczjk/g78;->$contentWindowInsets:Llyiahf/vczjk/kna;

    iget-object v7, p0, Llyiahf/vczjk/g78;->$bottomBar:Llyiahf/vczjk/ze3;

    iget p1, p0, Llyiahf/vczjk/g78;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/k78;->OooO0OO(ZILlyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/kna;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
