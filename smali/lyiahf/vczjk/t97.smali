.class public final synthetic Llyiahf/vczjk/t97;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:F

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JFJIFII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t97;->OooOOO0:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/t97;->OooOOO:Llyiahf/vczjk/kl5;

    iput-wide p3, p0, Llyiahf/vczjk/t97;->OooOOOO:J

    iput p5, p0, Llyiahf/vczjk/t97;->OooOOOo:F

    iput-wide p6, p0, Llyiahf/vczjk/t97;->OooOOo0:J

    iput p8, p0, Llyiahf/vczjk/t97;->OooOOo:I

    iput p9, p0, Llyiahf/vczjk/t97;->OooOOoo:F

    iput p11, p0, Llyiahf/vczjk/t97;->OooOo00:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0xc31

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v10

    iget v8, p0, Llyiahf/vczjk/t97;->OooOOoo:F

    iget v11, p0, Llyiahf/vczjk/t97;->OooOo00:I

    iget-object v0, p0, Llyiahf/vczjk/t97;->OooOOO0:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/t97;->OooOOO:Llyiahf/vczjk/kl5;

    iget-wide v2, p0, Llyiahf/vczjk/t97;->OooOOOO:J

    iget v4, p0, Llyiahf/vczjk/t97;->OooOOOo:F

    iget-wide v5, p0, Llyiahf/vczjk/t97;->OooOOo0:J

    iget v7, p0, Llyiahf/vczjk/t97;->OooOOo:I

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/ea7;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JFJIFLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
