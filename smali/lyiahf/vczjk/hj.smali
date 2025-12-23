.class public final Llyiahf/vczjk/hj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/df3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/df3;"
        }
    .end annotation
.end field

.field final synthetic $contentAlignment:Llyiahf/vczjk/o4;

.field final synthetic $contentKey:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $this_AnimatedContent:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic $transitionSpec:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/hj;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/hj;->$transitionSpec:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/hj;->$contentAlignment:Llyiahf/vczjk/o4;

    iput-object p5, p0, Llyiahf/vczjk/hj;->$contentKey:Llyiahf/vczjk/oe3;

    iput-object p6, p0, Llyiahf/vczjk/hj;->$content:Llyiahf/vczjk/df3;

    iput p7, p0, Llyiahf/vczjk/hj;->$$changed:I

    iput p8, p0, Llyiahf/vczjk/hj;->$$default:I

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

    iget-object v0, p0, Llyiahf/vczjk/hj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    iget-object v1, p0, Llyiahf/vczjk/hj;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/hj;->$transitionSpec:Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/hj;->$contentAlignment:Llyiahf/vczjk/o4;

    iget-object v4, p0, Llyiahf/vczjk/hj;->$contentKey:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/hj;->$content:Llyiahf/vczjk/df3;

    iget p1, p0, Llyiahf/vczjk/hj;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget v8, p0, Llyiahf/vczjk/hj;->$$default:I

    invoke-static/range {v0 .. v8}, Landroidx/compose/animation/OooO00o;->OooO0O0(Llyiahf/vczjk/bz9;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
