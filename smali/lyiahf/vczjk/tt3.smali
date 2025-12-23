.class public final Llyiahf/vczjk/tt3;
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
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/ze3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tt3;->$onClick:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/tt3;->$modifier:Llyiahf/vczjk/kl5;

    iput-boolean p3, p0, Llyiahf/vczjk/tt3;->$enabled:Z

    iput-object p4, p0, Llyiahf/vczjk/tt3;->$interactionSource:Llyiahf/vczjk/rr5;

    iput-object p5, p0, Llyiahf/vczjk/tt3;->$content:Llyiahf/vczjk/ze3;

    iput p6, p0, Llyiahf/vczjk/tt3;->$$changed:I

    iput p7, p0, Llyiahf/vczjk/tt3;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/tt3;->$onClick:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/tt3;->$modifier:Llyiahf/vczjk/kl5;

    iget-boolean v2, p0, Llyiahf/vczjk/tt3;->$enabled:Z

    iget-object v3, p0, Llyiahf/vczjk/tt3;->$interactionSource:Llyiahf/vczjk/rr5;

    iget-object v4, p0, Llyiahf/vczjk/tt3;->$content:Llyiahf/vczjk/ze3;

    iget p1, p0, Llyiahf/vczjk/tt3;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget v7, p0, Llyiahf/vczjk/tt3;->$$default:I

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/ut3;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
