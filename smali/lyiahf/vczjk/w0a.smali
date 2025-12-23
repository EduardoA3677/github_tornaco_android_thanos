.class public final Llyiahf/vczjk/w0a;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field I$0:I

.field I$1:I

.field I$2:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/b1a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b1a;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/w0a;->this$0:Llyiahf/vczjk/b1a;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iput-object p1, p0, Llyiahf/vczjk/w0a;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/w0a;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/w0a;->label:I

    iget-object p1, p0, Llyiahf/vczjk/w0a;->this$0:Llyiahf/vczjk/b1a;

    const/4 v0, 0x0

    const/4 v1, 0x0

    invoke-static {p1, v0, v1, p0}, Llyiahf/vczjk/b1a;->OooO0OO(Llyiahf/vczjk/b1a;Llyiahf/vczjk/ay9;ILlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
