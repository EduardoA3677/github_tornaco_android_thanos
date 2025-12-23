.class public final Llyiahf/vczjk/kc;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $minTouchTargetSize:J

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $offsetProvider:Llyiahf/vczjk/v86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v86;Llyiahf/vczjk/kl5;JII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kc;->$offsetProvider:Llyiahf/vczjk/v86;

    iput-object p2, p0, Llyiahf/vczjk/kc;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p3, p0, Llyiahf/vczjk/kc;->$minTouchTargetSize:J

    iput p5, p0, Llyiahf/vczjk/kc;->$$changed:I

    iput p6, p0, Llyiahf/vczjk/kc;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/kc;->$offsetProvider:Llyiahf/vczjk/v86;

    iget-object v1, p0, Llyiahf/vczjk/kc;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v2, p0, Llyiahf/vczjk/kc;->$minTouchTargetSize:J

    iget p1, p0, Llyiahf/vczjk/kc;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget v6, p0, Llyiahf/vczjk/kc;->$$default:I

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/qc;->OooO00o(Llyiahf/vczjk/v86;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
