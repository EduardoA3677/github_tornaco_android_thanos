.class public final Llyiahf/vczjk/nf8;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field L$0:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/qf8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qf8;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qf8;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nf8;->this$0:Llyiahf/vczjk/qf8;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/nf8;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/nf8;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/nf8;->label:I

    iget-object p1, p0, Llyiahf/vczjk/nf8;->this$0:Llyiahf/vczjk/qf8;

    const/4 v0, 0x0

    invoke-virtual {p1, v0, p0}, Llyiahf/vczjk/qf8;->OooO00o(Llyiahf/vczjk/li6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
