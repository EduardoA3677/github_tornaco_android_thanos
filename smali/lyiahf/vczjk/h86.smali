.class public final Llyiahf/vczjk/h86;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/i86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i86;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/h86;->this$0:Llyiahf/vczjk/i86;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/h86;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/h86;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/h86;->label:I

    iget-object p1, p0, Llyiahf/vczjk/h86;->this$0:Llyiahf/vczjk/i86;

    const/4 v0, 0x0

    invoke-virtual {p1, v0, p0}, Llyiahf/vczjk/i86;->OooO00o(Llyiahf/vczjk/q0a;Llyiahf/vczjk/zo1;)V

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method
