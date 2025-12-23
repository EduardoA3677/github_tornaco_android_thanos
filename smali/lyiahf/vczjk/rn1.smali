.class public final Llyiahf/vczjk/rn1;
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

.field final synthetic $contextMenuBuilderBlock:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $enabled:Z

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onDismiss:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $onOpenGesture:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $state:Llyiahf/vczjk/eo1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eo1;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/ze3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rn1;->$state:Llyiahf/vczjk/eo1;

    iput-object p2, p0, Llyiahf/vczjk/rn1;->$onDismiss:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/rn1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/rn1;->$modifier:Llyiahf/vczjk/kl5;

    iput-boolean p5, p0, Llyiahf/vczjk/rn1;->$enabled:Z

    iput-object p6, p0, Llyiahf/vczjk/rn1;->$onOpenGesture:Llyiahf/vczjk/le3;

    iput-object p7, p0, Llyiahf/vczjk/rn1;->$content:Llyiahf/vczjk/ze3;

    iput p8, p0, Llyiahf/vczjk/rn1;->$$changed:I

    iput p9, p0, Llyiahf/vczjk/rn1;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/rn1;->$state:Llyiahf/vczjk/eo1;

    iget-object v1, p0, Llyiahf/vczjk/rn1;->$onDismiss:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/rn1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/rn1;->$modifier:Llyiahf/vczjk/kl5;

    iget-boolean v4, p0, Llyiahf/vczjk/rn1;->$enabled:Z

    iget-object v5, p0, Llyiahf/vczjk/rn1;->$onOpenGesture:Llyiahf/vczjk/le3;

    iget-object v6, p0, Llyiahf/vczjk/rn1;->$content:Llyiahf/vczjk/ze3;

    iget p1, p0, Llyiahf/vczjk/rn1;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget v9, p0, Llyiahf/vczjk/rn1;->$$default:I

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/c6a;->OooOO0(Llyiahf/vczjk/eo1;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
