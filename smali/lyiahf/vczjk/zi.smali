.class public final Llyiahf/vczjk/zi;
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

.field final synthetic $label:Ljava/lang/String;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $targetState:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
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
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zi;->$targetState:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/zi;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/zi;->$transitionSpec:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/zi;->$contentAlignment:Llyiahf/vczjk/o4;

    iput-object p5, p0, Llyiahf/vczjk/zi;->$label:Ljava/lang/String;

    iput-object p6, p0, Llyiahf/vczjk/zi;->$contentKey:Llyiahf/vczjk/oe3;

    iput-object p7, p0, Llyiahf/vczjk/zi;->$content:Llyiahf/vczjk/df3;

    iput p8, p0, Llyiahf/vczjk/zi;->$$changed:I

    iput p9, p0, Llyiahf/vczjk/zi;->$$default:I

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

    iget-object v0, p0, Llyiahf/vczjk/zi;->$targetState:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/zi;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/zi;->$transitionSpec:Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/zi;->$contentAlignment:Llyiahf/vczjk/o4;

    iget-object v4, p0, Llyiahf/vczjk/zi;->$label:Ljava/lang/String;

    iget-object v5, p0, Llyiahf/vczjk/zi;->$contentKey:Llyiahf/vczjk/oe3;

    iget-object v6, p0, Llyiahf/vczjk/zi;->$content:Llyiahf/vczjk/df3;

    iget p1, p0, Llyiahf/vczjk/zi;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget v9, p0, Llyiahf/vczjk/zi;->$$default:I

    invoke-static/range {v0 .. v9}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
