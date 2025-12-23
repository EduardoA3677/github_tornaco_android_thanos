.class public final Llyiahf/vczjk/yo3;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/cp3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cp3;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yo3;->this$0:Llyiahf/vczjk/cp3;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/yo3;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/yo3;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/yo3;->label:I

    iget-object p1, p0, Llyiahf/vczjk/yo3;->this$0:Llyiahf/vczjk/cp3;

    invoke-static {p1, p0}, Llyiahf/vczjk/cp3;->o00000OO(Llyiahf/vczjk/cp3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
