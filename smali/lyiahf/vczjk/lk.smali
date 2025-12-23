.class public final Llyiahf/vczjk/lk;
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

.field final synthetic $enter:Llyiahf/vczjk/ep2;

.field final synthetic $exit:Llyiahf/vczjk/ct2;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onLookaheadMeasured:Llyiahf/vczjk/za6;

.field final synthetic $shouldDisposeBlock:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $transition:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic $visible:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lk;->$transition:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/lk;->$visible:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/lk;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p4, p0, Llyiahf/vczjk/lk;->$enter:Llyiahf/vczjk/ep2;

    iput-object p5, p0, Llyiahf/vczjk/lk;->$exit:Llyiahf/vczjk/ct2;

    iput-object p6, p0, Llyiahf/vczjk/lk;->$shouldDisposeBlock:Llyiahf/vczjk/ze3;

    iput-object p7, p0, Llyiahf/vczjk/lk;->$content:Llyiahf/vczjk/bf3;

    iput p8, p0, Llyiahf/vczjk/lk;->$$changed:I

    iput p9, p0, Llyiahf/vczjk/lk;->$$default:I

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

    iget-object v0, p0, Llyiahf/vczjk/lk;->$transition:Llyiahf/vczjk/bz9;

    iget-object v1, p0, Llyiahf/vczjk/lk;->$visible:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/lk;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, p0, Llyiahf/vczjk/lk;->$enter:Llyiahf/vczjk/ep2;

    iget-object v4, p0, Llyiahf/vczjk/lk;->$exit:Llyiahf/vczjk/ct2;

    iget-object v5, p0, Llyiahf/vczjk/lk;->$shouldDisposeBlock:Llyiahf/vczjk/ze3;

    iget-object v6, p0, Llyiahf/vczjk/lk;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/lk;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget v9, p0, Llyiahf/vczjk/lk;->$$default:I

    invoke-static/range {v0 .. v9}, Landroidx/compose/animation/OooO0O0;->OooO00o(Llyiahf/vczjk/bz9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
