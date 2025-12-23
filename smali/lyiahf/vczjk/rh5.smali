.class public final Llyiahf/vczjk/rh5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $enabled:Z

.field final synthetic $interactionSource:Llyiahf/vczjk/rr5;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onClick:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bi6;Llyiahf/vczjk/rr5;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rh5;->$onClick:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/rh5;->$modifier:Llyiahf/vczjk/kl5;

    iput-boolean p3, p0, Llyiahf/vczjk/rh5;->$enabled:Z

    iput-object p4, p0, Llyiahf/vczjk/rh5;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-object p5, p0, Llyiahf/vczjk/rh5;->$interactionSource:Llyiahf/vczjk/rr5;

    iput-object p6, p0, Llyiahf/vczjk/rh5;->$content:Llyiahf/vczjk/bf3;

    iput p7, p0, Llyiahf/vczjk/rh5;->$$changed:I

    iput p8, p0, Llyiahf/vczjk/rh5;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/rh5;->$onClick:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/rh5;->$modifier:Llyiahf/vczjk/kl5;

    iget-boolean v2, p0, Llyiahf/vczjk/rh5;->$enabled:Z

    iget-object v3, p0, Llyiahf/vczjk/rh5;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-object v4, p0, Llyiahf/vczjk/rh5;->$interactionSource:Llyiahf/vczjk/rr5;

    iget-object v5, p0, Llyiahf/vczjk/rh5;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/rh5;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget v8, p0, Llyiahf/vczjk/rh5;->$$default:I

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/th5;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bi6;Llyiahf/vczjk/rr5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
