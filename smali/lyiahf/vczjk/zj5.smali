.class public final synthetic Llyiahf/vczjk/zj5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/p29;

.field public final synthetic OooOOO0:J


# direct methods
.method public synthetic constructor <init>(JLlyiahf/vczjk/p29;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/zj5;->OooOOO0:J

    iput-object p3, p0, Llyiahf/vczjk/zj5;->OooOOO:Llyiahf/vczjk/p29;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/hg2;

    iget-object p1, p0, Llyiahf/vczjk/zj5;->OooOOO:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    const/4 v1, 0x0

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v7

    const/4 v8, 0x0

    const/4 v9, 0x0

    iget-wide v1, p0, Llyiahf/vczjk/zj5;->OooOOO0:J

    const-wide/16 v3, 0x0

    const-wide/16 v5, 0x0

    const/16 v10, 0x76

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
