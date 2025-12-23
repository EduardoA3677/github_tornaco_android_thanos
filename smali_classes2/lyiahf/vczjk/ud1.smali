.class public final synthetic Llyiahf/vczjk/ud1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/rd1;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:F

.field public final synthetic OooOOoo:F

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:I

.field public final synthetic OooOo0O:J

.field public final synthetic OooOo0o:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rd1;FJFJFIIJII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ud1;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/ud1;->OooOOO:Llyiahf/vczjk/rd1;

    iput p3, p0, Llyiahf/vczjk/ud1;->OooOOOO:F

    iput-wide p4, p0, Llyiahf/vczjk/ud1;->OooOOOo:J

    iput p6, p0, Llyiahf/vczjk/ud1;->OooOOo0:F

    iput-wide p7, p0, Llyiahf/vczjk/ud1;->OooOOo:J

    iput p9, p0, Llyiahf/vczjk/ud1;->OooOOoo:F

    iput p10, p0, Llyiahf/vczjk/ud1;->OooOo00:I

    iput p11, p0, Llyiahf/vczjk/ud1;->OooOo0:I

    iput-wide p12, p0, Llyiahf/vczjk/ud1;->OooOo0O:J

    iput p15, p0, Llyiahf/vczjk/ud1;->OooOo0o:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v14, p1

    check-cast v14, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const v1, 0xc00001

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v15

    iget-object v2, v0, Llyiahf/vczjk/ud1;->OooOOO:Llyiahf/vczjk/rd1;

    iget-wide v12, v0, Llyiahf/vczjk/ud1;->OooOo0O:J

    iget v1, v0, Llyiahf/vczjk/ud1;->OooOo0o:I

    move/from16 v16, v1

    iget-object v1, v0, Llyiahf/vczjk/ud1;->OooOOO0:Llyiahf/vczjk/kl5;

    iget v3, v0, Llyiahf/vczjk/ud1;->OooOOOO:F

    iget-wide v4, v0, Llyiahf/vczjk/ud1;->OooOOOo:J

    iget v6, v0, Llyiahf/vczjk/ud1;->OooOOo0:F

    iget-wide v7, v0, Llyiahf/vczjk/ud1;->OooOOo:J

    iget v9, v0, Llyiahf/vczjk/ud1;->OooOOoo:F

    iget v10, v0, Llyiahf/vczjk/ud1;->OooOo00:I

    iget v11, v0, Llyiahf/vczjk/ud1;->OooOo0:I

    invoke-static/range {v1 .. v16}, Llyiahf/vczjk/rs;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rd1;FJFJFIIJLlyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
