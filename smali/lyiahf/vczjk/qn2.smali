.class public final Llyiahf/vczjk/qn2;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field I$0:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field L$4:Ljava/lang/Object;

.field L$5:Ljava/lang/Object;

.field L$6:Ljava/lang/Object;

.field L$7:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/wn2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wn2;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qn2;->this$0:Llyiahf/vczjk/wn2;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    iput-object p1, p0, Llyiahf/vczjk/qn2;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/qn2;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/qn2;->label:I

    iget-object v0, p0, Llyiahf/vczjk/qn2;->this$0:Llyiahf/vczjk/wn2;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v7, p0

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/wn2;->OooO00o(Llyiahf/vczjk/wn2;Llyiahf/vczjk/by8;Llyiahf/vczjk/f71;Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hf6;Llyiahf/vczjk/jr2;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
