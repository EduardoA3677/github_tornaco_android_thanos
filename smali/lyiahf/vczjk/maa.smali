.class public final Llyiahf/vczjk/maa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $beforeFrame:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $durationScale:F

.field final synthetic this$0:Llyiahf/vczjk/oaa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oaa;FLlyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/maa;->this$0:Llyiahf/vczjk/oaa;

    iput p2, p0, Llyiahf/vczjk/maa;->$durationScale:F

    iput-object p3, p0, Llyiahf/vczjk/maa;->$beforeFrame:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/maa;->this$0:Llyiahf/vczjk/oaa;

    iget-wide v2, p1, Llyiahf/vczjk/oaa;->OooO0O0:J

    const-wide/high16 v4, -0x8000000000000000L

    cmp-long v2, v2, v4

    if-nez v2, :cond_0

    iput-wide v0, p1, Llyiahf/vczjk/oaa;->OooO0O0:J

    :cond_0
    new-instance v6, Llyiahf/vczjk/zl;

    iget v2, p1, Llyiahf/vczjk/oaa;->OooO0o0:F

    invoke-direct {v6, v2}, Llyiahf/vczjk/zl;-><init>(F)V

    iget v3, p0, Llyiahf/vczjk/maa;->$durationScale:F

    const/4 v4, 0x0

    cmpg-float v4, v3, v4

    sget-object v7, Llyiahf/vczjk/oaa;->OooO0o:Llyiahf/vczjk/zl;

    if-nez v4, :cond_1

    new-instance v3, Llyiahf/vczjk/zl;

    invoke-direct {v3, v2}, Llyiahf/vczjk/zl;-><init>(F)V

    iget-object v2, p1, Llyiahf/vczjk/oaa;->OooO0OO:Llyiahf/vczjk/zl;

    iget-object p1, p1, Llyiahf/vczjk/oaa;->OooO00o:Llyiahf/vczjk/yda;

    invoke-interface {p1, v3, v7, v2}, Llyiahf/vczjk/yda;->OooO0o0(Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)J

    move-result-wide v2

    :goto_0
    move-wide v4, v2

    goto :goto_1

    :cond_1
    iget-wide v4, p1, Llyiahf/vczjk/oaa;->OooO0O0:J

    sub-long v4, v0, v4

    long-to-float p1, v4

    div-float/2addr p1, v3

    float-to-double v2, p1

    invoke-static {v2, v3}, Llyiahf/vczjk/ye5;->Oooo00o(D)J

    move-result-wide v2

    goto :goto_0

    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/maa;->this$0:Llyiahf/vczjk/oaa;

    iget-object v3, p1, Llyiahf/vczjk/oaa;->OooO00o:Llyiahf/vczjk/yda;

    iget-object v8, p1, Llyiahf/vczjk/oaa;->OooO0OO:Llyiahf/vczjk/zl;

    invoke-interface/range {v3 .. v8}, Llyiahf/vczjk/yda;->OooO0oo(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zl;

    iget p1, p1, Llyiahf/vczjk/zl;->OooO00o:F

    iget-object v2, p0, Llyiahf/vczjk/maa;->this$0:Llyiahf/vczjk/oaa;

    iget-object v3, v2, Llyiahf/vczjk/oaa;->OooO00o:Llyiahf/vczjk/yda;

    iget-object v8, v2, Llyiahf/vczjk/oaa;->OooO0OO:Llyiahf/vczjk/zl;

    invoke-interface/range {v3 .. v8}, Llyiahf/vczjk/yda;->OooOO0o(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/zl;

    iput-object v3, v2, Llyiahf/vczjk/oaa;->OooO0OO:Llyiahf/vczjk/zl;

    iget-object v2, p0, Llyiahf/vczjk/maa;->this$0:Llyiahf/vczjk/oaa;

    iput-wide v0, v2, Llyiahf/vczjk/oaa;->OooO0O0:J

    iget v0, v2, Llyiahf/vczjk/oaa;->OooO0o0:F

    sub-float/2addr v0, p1

    iput p1, v2, Llyiahf/vczjk/oaa;->OooO0o0:F

    iget-object p1, p0, Llyiahf/vczjk/maa;->$beforeFrame:Llyiahf/vczjk/oe3;

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
