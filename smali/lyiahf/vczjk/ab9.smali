.class public final Llyiahf/vczjk/ab9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animation:Llyiahf/vczjk/yk;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/yk;"
        }
    .end annotation
.end field

.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $durationScale:F

.field final synthetic $lateInitScope:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $this_animate:Llyiahf/vczjk/xl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xl;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;FLlyiahf/vczjk/yk;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ab9;->$lateInitScope:Llyiahf/vczjk/hl7;

    iput p2, p0, Llyiahf/vczjk/ab9;->$durationScale:F

    iput-object p3, p0, Llyiahf/vczjk/ab9;->$animation:Llyiahf/vczjk/yk;

    iput-object p4, p0, Llyiahf/vczjk/ab9;->$this_animate:Llyiahf/vczjk/xl;

    iput-object p5, p0, Llyiahf/vczjk/ab9;->$block:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    move-result-wide v1

    iget-object p1, p0, Llyiahf/vczjk/ab9;->$lateInitScope:Llyiahf/vczjk/hl7;

    iget-object p1, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/fl;

    iget v3, p0, Llyiahf/vczjk/ab9;->$durationScale:F

    iget-object v4, p0, Llyiahf/vczjk/ab9;->$animation:Llyiahf/vczjk/yk;

    iget-object v5, p0, Llyiahf/vczjk/ab9;->$this_animate:Llyiahf/vczjk/xl;

    iget-object v6, p0, Llyiahf/vczjk/ab9;->$block:Llyiahf/vczjk/oe3;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/vc6;->OooOOo(Llyiahf/vczjk/fl;JFLlyiahf/vczjk/yk;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
