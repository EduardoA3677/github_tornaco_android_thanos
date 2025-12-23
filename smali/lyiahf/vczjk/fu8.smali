.class public final synthetic Llyiahf/vczjk/fu8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/gt8;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:J

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:J


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/gt8;Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJJJJI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fu8;->OooOOO0:Llyiahf/vczjk/gt8;

    iput-object p2, p0, Llyiahf/vczjk/fu8;->OooOOO:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/fu8;->OooOOOO:Llyiahf/vczjk/qj8;

    iput-wide p4, p0, Llyiahf/vczjk/fu8;->OooOOOo:J

    iput-wide p6, p0, Llyiahf/vczjk/fu8;->OooOOo0:J

    iput-wide p8, p0, Llyiahf/vczjk/fu8;->OooOOo:J

    iput-wide p10, p0, Llyiahf/vczjk/fu8;->OooOOoo:J

    iput-wide p12, p0, Llyiahf/vczjk/fu8;->OooOo00:J

    iput p14, p0, Llyiahf/vczjk/fu8;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v14, p1

    check-cast v14, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, v0, Llyiahf/vczjk/fu8;->OooOo0:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v15

    iget-wide v10, v0, Llyiahf/vczjk/fu8;->OooOOoo:J

    iget-wide v12, v0, Llyiahf/vczjk/fu8;->OooOo00:J

    iget-object v1, v0, Llyiahf/vczjk/fu8;->OooOOO0:Llyiahf/vczjk/gt8;

    iget-object v2, v0, Llyiahf/vczjk/fu8;->OooOOO:Llyiahf/vczjk/kl5;

    iget-object v3, v0, Llyiahf/vczjk/fu8;->OooOOOO:Llyiahf/vczjk/qj8;

    iget-wide v4, v0, Llyiahf/vczjk/fu8;->OooOOOo:J

    iget-wide v6, v0, Llyiahf/vczjk/fu8;->OooOOo0:J

    iget-wide v8, v0, Llyiahf/vczjk/fu8;->OooOOo:J

    invoke-static/range {v1 .. v15}, Llyiahf/vczjk/lu8;->OooO0OO(Llyiahf/vczjk/gt8;Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJJJJLlyiahf/vczjk/rf1;I)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
